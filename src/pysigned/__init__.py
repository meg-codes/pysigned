from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("pysigned")
except PackageNotFoundError:
    # Package is not installed (e.g., running locally during development)
    __version__ = "0.0.0"

from .backends import Backend

from .keys import (
    Ed25519KeyPair,
    Ed25519PublicKey,
    HMACKey,
    KeySet,
)

from .signature import URLAuth

__all__ = [
    "Backend",
    "Ed25519KeyPair",
    "Ed25519PublicKey",
    "HMACKey",
    "KeySet",
    "URLAuth",
]
