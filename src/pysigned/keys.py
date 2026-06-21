import os
import json
import hashlib
from base64 import urlsafe_b64decode
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Self, cast, Iterator
from cryptography.hazmat.primitives.asymmetric import ed25519

if TYPE_CHECKING:
    from .backends import Backend, KeyValue

DIGEST = "sha512"
# HMAC keys must be at least the digest's output size (NIST SP 800-107).
MIN_KEY_BYTES = hashlib.new(DIGEST).digest_size


class KeyLike:
    id: str = ""

    def _id_bytes(self) -> bytes:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{type(self).__name__} id={self.id}, bytes={self._id_bytes().hex()[:5]}...>"

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True, eq=False, repr=False)
class Key(KeyLike):
    """A signing/verifying key: raw bytes plus a stable id.

    Subclasses supply two hooks: ``_validate`` (raise on bad key material) and
    ``_id_bytes`` (the bytes the ``id`` fingerprint is hashed from).

    ``_id_bytes`` is **not** "the public part" of the key. It is only what the
    fingerprint is computed over. A symmetric HMAC key has no public counterpart,
    so its ``_id_bytes`` is the *secret* key itself -- safe to hash into an id only
    because SHA-256 is one-way, and safe to show in ``repr`` only because ``repr``
    truncates. An asymmetric Ed25519 key uses its genuinely public bytes.
    """

    key: bytes
    id: str = ""

    def __post_init__(self) -> None:
        self._validate()
        # Own an immutable copy so a mutable bytearray argument can't change
        # underneath the frozen instance.
        object.__setattr__(self, "key", bytes(self.key))
        if not self.id:
            object.__setattr__(self, "id", hashlib.sha512(self._id_bytes()).hexdigest())

    def _validate(self) -> None:
        raise NotImplementedError

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Key):
            other = other.key
        return self.key == other

    def __bytes__(self):
        return self.key


class HMACKey(Key):
    """A symmetric HMAC key."""

    def _validate(self) -> None:
        if len(self.key) < MIN_KEY_BYTES:
            raise ValueError(
                f"key is {len(self.key)} bytes; "
                f"{DIGEST} requires keys of at least {MIN_KEY_BYTES} bytes"
            )

    def _id_bytes(self) -> bytes:
        return self.key


class Ed25519PublicKey(Key):
    """A verify-only Ed25519 public key, with no signing capability."""

    public_key: ed25519.Ed25519PublicKey

    def _validate(self) -> None:
        object.__setattr__(
            self, "public_key", ed25519.Ed25519PublicKey.from_public_bytes(self.key)
        )

    def _id_bytes(self) -> bytes:
        return self.key


class Ed25519KeyPair(KeyLike):
    """An Ed25519 keypair, wrapping a private key and its public key.

    Can both sign and verify. Its ``id`` is fingerprinted from the public
    key, so it matches the id of the corresponding :class:`Ed25519PublicKey`, and
    neither the id nor the repr ever expose the seed.
    """

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | bytes,
        public_key: ed25519.Ed25519PublicKey | bytes | None = None,
        id: str = "",
    ):
        if isinstance(private_key, bytes):
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        if isinstance(public_key, bytes):
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)

        self.private_key = private_key
        if public_key:
            if (
                cast(ed25519.Ed25519PublicKey, public_key).public_bytes_raw()
                != self.private_key.public_key().public_bytes_raw()
            ):
                raise ValueError("Mismatch private and public ed25519 keys")
        self.public_key = (
            cast(ed25519.Ed25519PublicKey, public_key) or self.private_key.public_key()
        )
        self.id = id or hashlib.sha512(self._id_bytes()).hexdigest()

    @classmethod
    def generate(cls, id: str = "") -> Self:
        """Generate a new random Ed25519 keypair."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        return cls(priv_key, pub_key, id)

    @classmethod
    def from_private_bytes(cls, seed: bytes, id: str = "") -> Self:
        """Build a keypair from a 32-byte Ed25519 private seed."""
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub_key = priv_key.public_key()
        return cls(priv_key, pub_key, id)

    def public(self) -> "Ed25519PublicKey":
        """The verify-only public key for this pair, sharing its id."""
        return Ed25519PublicKey(self.public_key.public_bytes_raw(), self.id)

    def __bytes__(self) -> bytes:
        """The raw public-key bytes (its public identity); never the seed."""
        return self.public_key.public_bytes_raw()

    def _id_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()


class KeySet:
    """An id-keyed, read-only collection of keys parsed by a backend.

    Keys of different algorithms may be mixed freely; signing and verifying each
    key dispatches on its type via the backend.
    """

    def __init__(self, keys: "Iterable[KeyValue]", backend: "Backend | None" = None):
        if backend is None:
            # Deferred to break the keys <-> backends import cycle: backends
            # imports the key types from this module, so Backend can't be
            # imported here at module load time.
            from .backends import Backend

            backend = Backend()
        self.backend = backend
        self._keys: Mapping[str, Key | Ed25519KeyPair] = MappingProxyType(
            {k.id: k for k in map(backend.parse_key, keys)}
        )

    def __getitem__(self, key: str) -> "Key | Ed25519KeyPair":
        return self._keys[key]

    def __iter__(self) -> Iterator[Key | Ed25519KeyPair]:
        return iter(self._keys.values())

    def __reversed__(self):
        return reversed(list(self._keys.values()))

    def __len__(self):
        return len(self._keys)

    @staticmethod
    def _unpadded_b64decode(s: str) -> bytes:
        padding_needed = -len(s) % 4
        padded = s + ("=" * padding_needed)
        return urlsafe_b64decode(padded)

    @classmethod
    def from_jwks(cls, jwks: dict[str, Any], backend: "Backend | None" = None) -> Self:
        """Build a KeySet from a JWKS (a ``{"keys": [...]}`` mapping of JWKs).

        Each JWK becomes an :class:`HMACKey`, :class:`Ed25519KeyPair`, or
        :class:`Ed25519PublicKey` depending on its ``kty``/``crv`` and whether a
        private component (``d``) is present.
        """
        if not (keys := jwks.get("keys")):
            raise ValueError("No 'keys' provided in JWKS.")
        collected = []
        for key in keys:
            kid: str = key.get("kid", "")
            match key:
                case {"kty": "OKP", "crv": "Ed25519", "x": public, "d": private}:
                    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                        (cls._unpadded_b64decode(private))
                    )
                    public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                        cls._unpadded_b64decode(public)
                    )
                    collected.append(Ed25519KeyPair(private_key, public_key, id=kid))
                case {"kty": "OKP", "crv": "Ed25519", "x": public}:
                    collected.append(
                        Ed25519PublicKey(cls._unpadded_b64decode(public), id=kid)
                    )
                case {"kty": "oct", "alg": "HS512", "k": private}:
                    collected.append(HMACKey(cls._unpadded_b64decode(private), id=kid))
                case _:
                    raise NotImplementedError("Unknown key type in jwks")
        return cls(collected, backend=backend)

    @classmethod
    def from_env(cls, environment_key: str, backend: "Backend | None" = None) -> Self:
        """Build a KeySet from a JWKS stored as JSON in an environment variable.

        Raises:
            ValueError: If ``environment_key`` is unset or empty.
        """
        if not (val := os.getenv(environment_key)):
            raise ValueError(f"{environment_key} unset, cannot import keyset.")
        jwks = json.loads(val)
        return cls.from_jwks(jwks, backend)
