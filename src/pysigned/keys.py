import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519


DIGEST = "sha512"
# HMAC keys must be at least the digest's output size (NIST SP 800-107).
MIN_KEY_BYTES = hashlib.new(DIGEST).digest_size
# Ed25519 seeds and public keys are both fixed at 32 bytes (RFC 8032).
ED25519_KEY_BYTES = 32


@dataclass(frozen=True, eq=False, repr=False)
class Key:
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

    def __post_init__(self):
        self._validate()
        # Own an immutable copy so a mutable bytearray argument can't change
        # underneath the frozen instance.
        object.__setattr__(self, "key", bytes(self.key))
        if not self.id:
            object.__setattr__(
                self, "id", hashlib.sha256(self._id_bytes()).hexdigest()
            )

    def _validate(self) -> None:
        raise NotImplementedError

    def _id_bytes(self) -> bytes:
        raise NotImplementedError

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Key):
            other = other.key
        return self.key == other

    def __bytes__(self):
        return self.key

    def __repr__(self):
        return f"<{type(self).__name__} id={self.id}, bytes={self._id_bytes().hex()[:5]}...>"


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


class Ed25519PrivateKey(Key):
    """An Ed25519 private key. ``key`` holds the 32-byte raw seed.

    Can both sign and verify. Its ``id`` is fingerprinted from the derived public
    key, so it matches the id of the corresponding :class:`Ed25519PublicKey`, and
    neither the id nor the repr ever expose the seed.
    """

    @classmethod
    def generate(cls, id: str = "") -> "Ed25519PrivateKey":
        raw = _ed25519.Ed25519PrivateKey.generate().private_bytes_raw()
        return cls(raw, id)

    @classmethod
    def from_private_bytes(cls, seed: bytes, id: str = "") -> "Ed25519PrivateKey":
        return cls(seed, id)

    def _validate(self) -> None:
        if len(self.key) != ED25519_KEY_BYTES:
            raise ValueError(
                f"Ed25519 private seed must be {ED25519_KEY_BYTES} bytes, "
                f"got {len(self.key)}"
            )

    def _crypto_key(self) -> _ed25519.Ed25519PrivateKey:
        return _ed25519.Ed25519PrivateKey.from_private_bytes(self.key)

    def public_bytes(self) -> bytes:
        return self._crypto_key().public_key().public_bytes_raw()

    def public_key(self) -> "Ed25519PublicKey":
        """The verify-side key, sharing this key's id."""
        return Ed25519PublicKey(self.public_bytes(), self.id)

    def _id_bytes(self) -> bytes:
        return self.public_bytes()


class Ed25519PublicKey(Key):
    """An Ed25519 public key. ``key`` holds the 32-byte raw public key. Verify only."""

    @classmethod
    def from_public_bytes(cls, public: bytes, id: str = "") -> "Ed25519PublicKey":
        return cls(public, id)

    def _validate(self) -> None:
        if len(self.key) != ED25519_KEY_BYTES:
            raise ValueError(
                f"Ed25519 public key must be {ED25519_KEY_BYTES} bytes, "
                f"got {len(self.key)}"
            )
        # Reject points that aren't valid public keys.
        _ed25519.Ed25519PublicKey.from_public_bytes(self.key)

    def _crypto_key(self) -> _ed25519.Ed25519PublicKey:
        return _ed25519.Ed25519PublicKey.from_public_bytes(self.key)

    def _id_bytes(self) -> bytes:
        return self.key
