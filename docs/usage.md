# Usage

## HMAC (symmetric)

The same secret signs and verifies. Use this when a single trusted service does
both. Keys must be at least 64 bytes (the SHA-512 digest size).

```python
import secrets
from pysigned import URLAuth

# A raw 64-byte secret is wrapped in an HMAC keyset automatically.
signer = URLAuth([secrets.token_bytes(64)], ttl=60)

signed = signer.sign("https://example.com/report?id=42&fmt=pdf")
# https://example.com/report?id=42&fmt=pdf&sig=...&exp=...

signer.verify(signed)                             # True
signer.verify(signed.replace("id=42", "id=99"))   # False — tampered
```

`ttl` is the number of seconds a signature stays valid (default: 10 minutes).
Once `exp` passes, [`verify`][pysigned.URLAuth.verify] returns `False`.

## Key rotation

Pass `(key_bytes, id)` tuples to give keys stable ids. The most recently added
key signs by default; every configured key is accepted on verify, so signatures
made with a rotated-out key keep working until they expire.

```python
import secrets
from pysigned import HMACKeySet, URLAuth

keys = HMACKeySet([
    (secrets.token_bytes(64), "k-2024"),  # old key, still trusted for verify
    (secrets.token_bytes(64), "k-2025"),  # newest -> used for signing
])
signer = URLAuth(keys, ttl=60)

# Sign with a specific key instead of the default:
signer = URLAuth(keys, signing_key_id="k-2024")
```

## Ed25519 (asymmetric)

A private key signs; a public key only verifies. Use this when you sign in one
place and verify somewhere less trusted — the verifier can't forge new
signatures.

```python
from pysigned import Ed25519KeySet, Ed25519PrivateKey, Ed25519PublicKey, URLAuth

# Signing side holds the private key.
private = Ed25519PrivateKey.generate("ed-2025")
signer = URLAuth(Ed25519KeySet([private]), ttl=60)
signed = signer.sign("https://example.com/download?file=archive.zip")

# Verifying side only needs the public key. It shares the private key's id.
public = Ed25519PublicKey.from_public_bytes(private.public_bytes(), private.id)
verifier = URLAuth(Ed25519KeySet([public]))

verifier.verify(signed)  # True
```

!!! note "Raw Ed25519 bytes are rejected"
    The Ed25519 backend will not accept raw bytes, because they are ambiguous
    between a private seed and a public key. Wrap them as
    [`Ed25519PrivateKey`][pysigned.Ed25519PrivateKey] or
    [`Ed25519PublicKey`][pysigned.Ed25519PublicKey] first.

## Ignoring query parameters

Parameters you don't want to be part of the signature (for example a tracking
token added downstream) can be excluded:

```python
signer = URLAuth(keys, ignore_query_params=["utm_source"])
```

## Clock skew

Allow a grace period past expiry to tolerate clock differences between signer
and verifier:

```python
signer.verify(signed, skew=30)  # accept up to 30s past exp
```

## Runnable example

A runnable demo of both backends lives in `examples/sign_urls.py`:

```sh
uv run python examples/sign_urls.py
```
