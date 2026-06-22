# How it works

## The signed message

[`URLAuth.sign`][pysigned.URLAuth.sign] builds a canonical byte string from the
URL and the expiry, then signs it with the configured backend:

1. The query is parsed and the `sig`/`exp` params — plus anything passed to
   `ignore_query_params` — are dropped, then re-encoded. This canonicalisation
   means signing and verification agree regardless of incoming encoding or the
   ordering of unrelated parameters.
2. The expiry, scheme, netloc, path, params, and canonical query are joined with
   newlines. A newline cannot appear in a URL component, so field boundaries can
   never be confused (e.g. a value ending in what looks like the next field).
3. The resulting `utf-8` bytes are handed to the backend's `sign`.

[`URLAuth.verify`][pysigned.URLAuth.verify] rebuilds the same message and checks
the signature against **every** configured key, so a signature made with a
rotated-out key still verifies until it expires. HMAC comparisons are
constant-time to avoid timing attacks.

## Keys and ids

Every key carries a stable `id`. If you don't supply one, it's a SHA-512
fingerprint:

- An [`HMACKey`][pysigned.HMACKey] fingerprints the secret itself (safe because
  SHA-512 is one-way, and `repr` truncates).
- An [`Ed25519KeyPair`][pysigned.Ed25519KeyPair] fingerprints its *public*
  bytes, so it shares the id of the matching
  [`Ed25519PublicKey`][pysigned.Ed25519PublicKey] and never leaks the seed.

## Backends

A [`Backend`][pysigned.Backend] owns the algorithm-specific work: parsing key
values into `Key` instances, signing, and verifying. It isn't tied to one
algorithm — each key already knows whether it is HMAC or Ed25519, so the backend
dispatches on the key's type. Everything algorithm-agnostic — URL
canonicalisation, expiry, key rotation — lives in `URLAuth`. A
[`KeySet`][pysigned.KeySet] pairs a collection of keys with the backend that
parses them, and a single keyset can mix HMAC and Ed25519 keys freely.
