"""Sample: signing and verifying URLs with pysigned.

Demonstrates both backends:

* HMAC  -- symmetric. The same secret signs and verifies, so whoever can
            verify can also forge. Good when one trusted party does both.
* Ed25519 -- asymmetric. A private key signs; a public key only verifies.
            Good when you sign in one place and verify somewhere less trusted.

Run with:  python examples/sign_urls.py
"""

import secrets

from pysigned import (
    Ed25519KeySet,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    HMACKeySet,
    Signer,
)


def hmac_demo() -> None:
    print("=== HMAC (symmetric) ===")

    # HMAC keys must be at least the digest size (64 bytes for sha512).
    # Pass (key_bytes, id) tuples so keys have stable, human-readable ids; the
    # most-recently-added key is the default signing key.
    keys = HMACKeySet(
        [
            (secrets.token_bytes(64), "k-2024"),  # old key, still trusted for verify
            (secrets.token_bytes(64), "k-2025"),  # newest -> used for signing
        ]
    )
    signer = Signer(keys, ttl=60)

    signed = signer.sign("https://example.com/report?id=42&fmt=pdf")
    print("signed: ", signed)
    print("verify: ", signer.verify(signed))

    tampered = signed.replace("id=42", "id=99")
    print("tampered verify:", signer.verify(tampered))
    print()


def ed25519_demo() -> None:
    print("=== Ed25519 (asymmetric) ===")

    # The signing side holds the private key.
    private = Ed25519PrivateKey.generate("ed-2025")
    signer = Signer(Ed25519KeySet([private]), ttl=60)

    signed = signer.sign("https://example.com/download?file=archive.zip")
    print("signed: ", signed)

    # The verifying side only needs the public key -- it cannot forge new
    # signatures. The public key shares the private key's id.
    public = Ed25519PublicKey.from_public_bytes(private.public_bytes(), private.id)
    verifier = Signer(Ed25519KeySet([public]))
    print("verify (public-only): ", verifier.verify(signed))

    tampered = signed.replace("archive.zip", "secrets.zip")
    print("tampered verify:      ", verifier.verify(tampered))
    print()


if __name__ == "__main__":
    hmac_demo()
    ed25519_demo()
