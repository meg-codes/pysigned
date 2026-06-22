import hmac

from cryptography.exceptions import InvalidSignature

from .keys import (
    DIGEST,
    Ed25519KeyPair,
    Ed25519PublicKey,
    HMACKey,
    Key,
    KeyLike,
)

# A user-supplied key: raw bytes / (bytes, id) become an HMACKey, or an
# already-wrapped key of any type (all of which are KeyLike).
KeyValue = tuple[bytes, str] | bytes | KeyLike


class Backend:
    """Parses key values and signs/verifies with whichever algorithm a key uses.

    Every key value already carries its own algorithm -- raw bytes and
    :class:`~pysigned.keys.HMACKey` are symmetric HMAC, while
    :class:`~pysigned.keys.Ed25519KeyPair` /
    :class:`~pysigned.keys.Ed25519PublicKey` are asymmetric -- so the backend
    dispatches on the key type rather than being fixed to one algorithm. A single
    :class:`KeySet` (and therefore a single :class:`~pysigned.signature.URLAuth`)
    can hold HMAC and Ed25519 keys together. Everything algorithm-agnostic (URL
    canonicalisation, expiry, key rotation) lives in
    :class:`~pysigned.signature.URLAuth`.

    Args:
        digest: Hash name used for HMAC keys (default ``sha512``). Ignored by
            Ed25519 keys.
    """

    def __init__(self, digest: str = DIGEST):
        self.digest = digest

    def parse_key(self, value: KeyValue) -> Key | Ed25519KeyPair:
        """Wrap a user-supplied key value as a :class:`~pysigned.keys.KeyLike`.

        Already-wrapped keys pass through; raw ``bytes`` or a ``(bytes, id)``
        tuple become an :class:`~pysigned.keys.HMACKey`. Ed25519 keys must be
        wrapped explicitly because raw bytes can't distinguish private from
        public -- and, now, HMAC from Ed25519.
        """
        match value:
            case HMACKey() | Ed25519KeyPair() | Ed25519PublicKey():
                return value
            case bytes():
                return HMACKey(value)
            case (_bytes, _id):
                if not isinstance(_bytes, bytes):
                    raise ValueError("Keys in tuples must be bytes")
                if not isinstance(_id, str):
                    raise ValueError("Key ids must be strings.")
                return HMACKey(_bytes, _id)
            case _:
                raise ValueError(f"Invalid key value: {value}")

    def sign(self, key: Key | Ed25519KeyPair, message: bytes) -> str:
        """Sign ``message`` with ``key``, returning a hex-encoded signature.

        Raises:
            TypeError: If ``key`` cannot sign (e.g. an :class:`Ed25519PublicKey`).
        """
        match key:
            case HMACKey():
                return hmac.new(bytes(key), message, self.digest).hexdigest()
            case Ed25519KeyPair():
                return key.private_key.sign(message).hex()
            case _:
                raise TypeError(
                    "signing requires an HMACKey or Ed25519KeyPair; "
                    f"got {type(key).__name__} (public keys cannot sign)"
                )

    def verify(
        self,
        key: Key | Ed25519KeyPair | Ed25519PublicKey,
        message: bytes,
        signature: str,
    ) -> bool:
        """Check ``signature`` against ``message`` for ``key``.

        Returns ``False`` (rather than raising) for an unrecognised key type or
        a malformed/invalid signature.
        """
        match key:
            case HMACKey():
                expected = hmac.new(bytes(key), message, self.digest).hexdigest()
                # Constant-time comparison to avoid timing attacks.
                return hmac.compare_digest(expected, signature)
            case Ed25519KeyPair() | Ed25519PublicKey():
                try:
                    key.public_key.verify(bytes.fromhex(signature), message)
                except (InvalidSignature, ValueError):
                    return False
            case _:
                return False
        return True
