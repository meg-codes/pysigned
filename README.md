# pysigned

Sign and verify URLs with an expiry. `pysigned` appends a tamper-proof
signature (`sig`) and an expiry (`exp`) to a URL's query string, so you can hand
out time-limited links — download links, password resets, webhook callbacks —
that can't be altered without invalidating the signature.

📖 **[Documentation](https://meg-codes.github.io/pysigned/)**

- **Two backends.** HMAC (symmetric) by default, or Ed25519 (asymmetric) when
  the signer and verifier shouldn't share a secret.
- **Key rotation.** Configure several keys; signing uses one, verification
  accepts any of them, so you can roll keys without breaking links in flight.
- **Canonical signing.** The query string is normalised before signing, so the
  signature survives re-encoding and reordering of unrelated parameters.

## Installation

Requires Python 3.13+.

```sh
uv add pysigned
```

```sh
pip install pysigned
```

## Usage

### HMAC (symmetric)

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
Once `exp` passes, `verify` returns `False`.

### Key rotation

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

### Ed25519 (asymmetric)

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

### Ignoring query parameters

Parameters you don't want to be part of the signature (for example a tracking
token added downstream) can be excluded:

```python
signer = URLAuth(keys, ignore_query_params=["utm_source"])
```

### Clock skew

Allow a grace period past expiry to tolerate clock differences between signer
and verifier:

```python
signer.verify(signed, skew=30)  # accept up to 30s past exp
```

## Examples

A runnable demo of both backends lives in [examples/sign_urls.py](examples/sign_urls.py):

```sh
uv run python examples/sign_urls.py
```

## How it works

`URLAuth.sign` builds a canonical byte string from the URL's scheme, host, path,
and query (with `sig`/`exp` and any ignored params removed), appends the expiry,
and signs it with the configured backend. Components are joined with newlines —
a byte that can't appear in a URL component — so field boundaries can never be
confused. `verify` rebuilds the same message and checks the signature against
every configured key in constant time.
