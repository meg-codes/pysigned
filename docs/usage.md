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
from pysigned import KeySet, URLAuth

keys = KeySet([
    (secrets.token_bytes(64), "k-2024"),  # old key, still trusted for verify
    (secrets.token_bytes(64), "k-2025"),  # newest -> used for signing
])
signer = URLAuth(keys, ttl=60)

# Sign with a specific key instead of the default:
signer = URLAuth(keys, signing_key_id="k-2024")
```

## Ed25519 (asymmetric)

A keypair signs; a public key only verifies. Use this when you sign in one
place and verify somewhere less trusted — the verifier holds only the public
key and can't forge new signatures.

```python
from pysigned import Ed25519KeyPair, KeySet, URLAuth

# Signing side holds the keypair (private key plus its public key).
keypair = Ed25519KeyPair.generate("ed-2025")
signer = URLAuth(KeySet([keypair]), ttl=60)
signed = signer.sign("https://example.com/download?file=archive.zip")

# Verifying side only needs the public key. It shares the keypair's id.
public = keypair.public()
verifier = URLAuth(KeySet([public]))

verifier.verify(signed)  # True
```

!!! note "Raw bytes are read as HMAC keys"
    A raw `bytes` value (or `(bytes, id)` tuple) is always wrapped as an
    [`HMACKey`][pysigned.HMACKey]. Ed25519 keys must be wrapped explicitly as
    [`Ed25519KeyPair`][pysigned.Ed25519KeyPair] or
    [`Ed25519PublicKey`][pysigned.Ed25519PublicKey], because raw bytes are
    ambiguous — both between HMAC and Ed25519, and between a private seed and a
    public key.

## Mixing algorithms

A single [`KeySet`][pysigned.KeySet] can hold both HMAC and Ed25519 keys.
`verify()` accepts any of them, so an audience can migrate from one algorithm to
another without a flag-day cutover — keep verifying old HMAC signatures while
signing new ones with Ed25519.

```python
from pysigned import Ed25519KeyPair, KeySet, URLAuth

keys = KeySet([
    (secrets.token_bytes(64), "legacy-hmac"),  # still trusted for verify
    Ed25519KeyPair.generate("ed-2025"),        # new signatures use this
])
signer = URLAuth(keys, signing_key_id="ed-2025")
```

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

## Generating keys

The `pysigned-gen-key` command (installed alongside the package) prints a
freshly generated key as JSON, for seeding config or secrets storage:

```sh
pysigned-gen-key --hmac
pysigned-gen-key --ed25519
```

Add `--jwks` to wrap the key in a `{"keys": [...]}` JWKS, which
[`KeySet.from_jwks`][pysigned.KeySet.from_jwks] can load directly:

```sh
pysigned-gen-key --ed25519 --jwks > keys.json
```

```python
import json
from pysigned import KeySet

keys = KeySet.from_jwks(json.load(open("keys.json")))
```

## Runnable example

A runnable demo of both backends lives in `examples/sign_urls.py`:

```sh
uv run python examples/sign_urls.py
```
