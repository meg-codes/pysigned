# pysigned

Sign and verify URLs with an expiry. `pysigned` appends a tamper-proof
signature (`sig`) and an expiry (`exp`) to a URL's query string, so you can hand
out time-limited links — download links, password resets, webhook callbacks —
that can't be altered without invalidating the signature.

- **Two backends.** HMAC (symmetric) by default, or Ed25519 (asymmetric) when
  the signer and verifier shouldn't share a secret.
- **No required dependencies.** The HMAC backend is pure standard library;
  Ed25519 is an optional `pysigned[ed25519]` extra.
- **Key rotation.** Configure several keys; signing uses one, verification
  accepts any of them, so you can roll keys without breaking links in flight.
- **Canonical signing.** The query string is normalised before signing, so the
  signature survives re-encoding and reordering of unrelated parameters.

## Quick start

```python
import secrets
from pysigned import URLAuth

signer = URLAuth([secrets.token_bytes(64)], ttl=60)

signed = signer.sign("https://example.com/report?id=42&fmt=pdf")
signer.verify(signed)  # True
```

Head to [Installation](installation.md) to get set up, then the
[Usage](usage.md) guide for the HMAC and Ed25519 workflows. The
[API reference](reference.md) is generated from the source.
