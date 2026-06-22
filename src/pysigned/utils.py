import argparse
import hashlib
import json
import secrets
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives.asymmetric import ed25519


def jwk_hmac() -> dict:
    """Generate a random HMAC key, returned as a JWK JSON string."""
    key = secrets.token_bytes(64)
    kid = urlsafe_b64encode(hashlib.sha512(key).digest()).decode()[0:12]
    k = urlsafe_b64encode(key).decode().rstrip("=")
    return {"kty": "oct", "use": "sig", "alg": "HS512", "kid": kid, "k": k}


def jwk_ed25519() -> dict:
    """Generate a random Ed25519 keypair, returned as a JWK JSON string."""
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    kid = urlsafe_b64encode(
        hashlib.sha512(public.public_bytes_raw()).digest()
    ).decode()[0:12]
    x = urlsafe_b64encode(public.public_bytes_raw()).decode().rstrip("=")
    d: str = urlsafe_b64encode(private.private_bytes_raw()).decode().rstrip("=")
    return {"kty": "OKP", "use": "sig", "crv": "Ed25519", "kid": kid, "x": x, "d": d}


def gen_key() -> None:
    """Entry point for the `pysigned-gen-key` CLI command.

    Prints a freshly generated key to stdout as a JWK, or as a JWKS
    (a `{"keys": [...]}` wrapper, suitable for [`KeySet.from_jwks`][pysigned.KeySet.from_jwks])
    when `--jwks` is passed.
    """
    parser = argparse.ArgumentParser(
        prog="pysigned-gen-key", description="Generate a signing key."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hmac", action="store_true", help="generate an HMAC key")
    group.add_argument("--ed25519", action="store_true", help="generate an Ed25519 key")
    parser.add_argument(
        "--jwks",
        action="store_true",
        help="wrap the key in a JWKS instead of emitting it bare",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Generate compact JSON for easy envvar storage.",
    )
    args = parser.parse_args()

    key = jwk_hmac() if args.hmac else jwk_ed25519()
    output = key
    if args.jwks:
        output = {"keys": [output]}

    if args.compact:
        print(json.dumps(output, separators=(",", ":")))
    else:
        print(json.dumps(output, indent=2))
