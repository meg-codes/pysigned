import hmac
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Generic, TypeVar

from cryptography.exceptions import InvalidSignature

from .keys import (
    DIGEST,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    HMACKey,
    Key,
)

K = TypeVar("K", bound=Key)


class Backend(ABC, Generic[K]):
    """Algorithm-specific key parsing and signing/verifying.

    A backend turns user-supplied key values into :class:`~pysigned.keys.Key`
    instances and knows how to sign a message and verify a signature with one.
    Everything algorithm-agnostic (URL canonicalisation, expiry, key rotation)
    lives in :class:`~pysigned.signature.Signer`.
    """

    @abstractmethod
    def parse_key(self, value) -> K:
        ...

    @abstractmethod
    def sign(self, key: K, message: bytes) -> str:
        ...

    @abstractmethod
    def verify(self, key: K, message: bytes, signature: str) -> bool:
        ...


HMACKeySetValue = tuple[bytes, str] | bytes | HMACKey


class HMACBackend(Backend[HMACKey]):
    def __init__(self, digest: str = DIGEST):
        self.digest = digest

    def parse_key(self, value: HMACKeySetValue) -> HMACKey:
        match value:
            case bytes():
                return HMACKey(value)
            case HMACKey():
                return value
            case (_bytes, _id):
                if not isinstance(_bytes, bytes):
                    raise ValueError("Keys in tuples must be bytes")
                if not isinstance(_id, str):
                    raise ValueError("Key ids must be strings.")
                return HMACKey(_bytes, _id)
            case _:
                raise ValueError(f"Invalid key value: {value}")

    def sign(self, key: HMACKey, message: bytes) -> str:
        return hmac.new(bytes(key), message, self.digest).hexdigest()

    def verify(self, key: HMACKey, message: bytes, signature: str) -> bool:
        expected = self.sign(key, message)
        # Constant-time comparison to avoid timing attacks.
        return hmac.compare_digest(expected, signature)


class Ed25519Backend(Backend[Key]):
    def parse_key(self, value) -> Key:
        if isinstance(value, (Ed25519PrivateKey, Ed25519PublicKey)):
            return value
        raise ValueError(
            "Ed25519 keys must be wrapped as Ed25519PrivateKey or "
            "Ed25519PublicKey; raw bytes are ambiguous (private vs public)."
        )

    def sign(self, key: Key, message: bytes) -> str:
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(
                "signing requires an Ed25519PrivateKey; "
                f"got {type(key).__name__} (public keys cannot sign)"
            )
        return key._crypto_key().sign(message).hex()

    def verify(self, key: Key, message: bytes, signature: str) -> bool:
        if isinstance(key, Ed25519PrivateKey):
            public = key._crypto_key().public_key()
        elif isinstance(key, Ed25519PublicKey):
            public = key._crypto_key()
        else:
            return False
        try:
            public.verify(bytes.fromhex(signature), message)
        except (InvalidSignature, ValueError):
            return False
        return True


class KeySet:
    """An id-keyed, read-only collection of keys parsed by a backend."""

    def __init__(self, keys: Iterable, backend: Backend):
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


class HMACKeySet(KeySet):
    def __init__(self, keys: Iterable, backend: HMACBackend | None = None):
        super().__init__(keys, backend or HMACBackend())


class Ed25519KeySet(KeySet):
    def __init__(self, keys: Iterable, backend: Ed25519Backend | None = None):
        super().__init__(keys, backend or Ed25519Backend())
