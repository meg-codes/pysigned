import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Self
from cryptography.hazmat.primitives.asymmetric import ed25519

if TYPE_CHECKING:
    from .backends import Backend

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
        private_key: ed25519.Ed25519PrivateKey,
        public_key: ed25519.Ed25519PublicKey | None = None,
        id: str = "",
    ):
        self.private_key = private_key
        self.public_key = public_key or self.private_key.public_key()
        self.id = id or hashlib.sha512(self._id_bytes()).hexdigest()

    @classmethod
    def generate(cls, id: str = "") -> Self:
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        return cls(priv_key, pub_key, id)

    @classmethod
    def from_private_bytes(cls, seed: bytes, id: str = "") -> Self:
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub_key = priv_key.public_key()
        return cls(priv_key, pub_key, id)

    def public(self) -> "Ed25519PublicKey":
        """The verify-only public key for this pair, sharing its id."""
        return Ed25519PublicKey(self.public_key.public_bytes_raw(), self.id)

    def _id_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()


class KeySet:
    """An id-keyed, read-only collection of keys parsed by a backend.

    Keys of different algorithms may be mixed freely; signing and verifying each
    key dispatches on its type via the backend.
    """

    def __init__(self, keys: Iterable, backend: "Backend | None" = None):
        if backend is None:
            # Deferred to break the keys <-> backends import cycle: backends
            # imports the key types from this module, so Backend can't be
            # imported here at module load time.
            from .backends import Backend

            backend = Backend()
        self.backend = backend
        self._keys: Mapping[str, Key] = MappingProxyType(
            {k.id: k for k in map(backend.parse_key, keys)}
        )

    def __getitem__(self, key: str):
        return self._keys[key]

    def __iter__(self):
        return iter(self._keys.values())

    def __reversed__(self):
        return reversed(list(self._keys.values()))

    def __len__(self):
        return len(self._keys)
