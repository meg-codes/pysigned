"""Tests for the key types and KeySet in pysigned.keys."""

import hashlib
import json
import socketserver
import threading
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from pysigned import __version__
from pysigned.backends import Backend
from pysigned.keys import (
    MIN_KEY_BYTES,
    Ed25519KeyPair,
    Ed25519PublicKey,
    HMACKey,
    Key,
    KeySet,
)


def kb(seed: bytes) -> bytes:
    """A valid (>= MIN_KEY_BYTES) HMAC key derived from a short seed.

    HMAC-SHA512 requires keys of at least 64 bytes; this lets tests keep using
    short readable labels while still satisfying the length requirement.
    Distinct seeds yield distinct keys.
    """
    return (seed * MIN_KEY_BYTES)[:MIN_KEY_BYTES]


def default_id(material: bytes) -> str:
    """The default key id: base64url of SHA-512(material), truncated to 12 chars."""
    return urlsafe_b64encode(hashlib.sha512(material).digest()).decode()[:12]


KEY = kb(b"k")
KEY_A = kb(b"a")
KEY_B = kb(b"b")

# Stable Ed25519 keypairs for tests that need determinism / two identities.
PAIR = Ed25519KeyPair.from_private_bytes(b"s" * 32)
PAIR_A = Ed25519KeyPair.from_private_bytes(b"a" * 32)
PAIR_B = Ed25519KeyPair.from_private_bytes(b"b" * 32)


# ---------------------------------------------------------------------------
# Key base class — abstract hooks raise NotImplementedError
# ---------------------------------------------------------------------------


def test_key_validate_not_implemented():
    with pytest.raises(NotImplementedError):
        Key(KEY)


def test_key_id_bytes_not_implemented():
    @dataclass(frozen=True, eq=False, repr=False)
    class _NoIdBytes(Key):
        def _validate(self):
            pass

    with pytest.raises(NotImplementedError):
        _NoIdBytes(KEY)


# ---------------------------------------------------------------------------
# HMACKey
# ---------------------------------------------------------------------------


def test_hmac_id_defaults_to_sha512_of_key():
    assert HMACKey(KEY).id == default_id(KEY)


def test_hmac_explicit_id_is_kept():
    assert HMACKey(KEY, id="kid-1").id == "kid-1"


def test_hmac_bytes_returns_raw_key():
    assert bytes(HMACKey(KEY)) == KEY


def test_hmac_equal_keys_hash_equal():
    assert hash(HMACKey(KEY)) == hash(HMACKey(KEY, id="other"))


@pytest.mark.parametrize(
    "other, expected",
    [
        (HMACKey(KEY, id="different-id"), True),  # same key, different id
        (HMACKey(KEY_A), False),  # different key
        (KEY, True),  # raw bytes equal
        (KEY_A, False),  # raw bytes unequal
        (object(), False),  # unrelated object (sentinel)
        (None, False),  # no .key attribute
    ],
)
def test_hmac_equality(other, expected):
    assert (HMACKey(KEY) == other) is expected


def test_hmac_repr_shows_id_and_truncated_key():
    rep = repr(HMACKey(KEY, id="kid-1"))
    assert "kid-1" in rep
    assert KEY.hex()[:5] in rep


def test_str_matches_repr():
    key = HMACKey(KEY, id="kid-1")
    assert str(key) == repr(key)


def test_min_key_bytes_matches_sha512_output():
    assert MIN_KEY_BYTES == 64


@pytest.mark.parametrize("length", [0, 1, 63])
def test_hmac_rejects_keys_shorter_than_digest_output(length):
    with pytest.raises(ValueError, match="at least 64 bytes"):
        HMACKey(b"x" * length)


@pytest.mark.parametrize("length", [64, 80, 128])
def test_hmac_accepts_keys_at_or_above_digest_output(length):
    # 64 is the minimum for sha512; longer keys are allowed, not just 64.
    assert len(bytes(HMACKey(b"x" * length))) == length


@pytest.mark.parametrize("attr", ["key", "id"])
def test_hmac_is_frozen(attr):
    key = HMACKey(KEY)
    with pytest.raises(AttributeError):
        setattr(key, attr, KEY_A)


def test_hmac_copies_key_so_source_mutation_is_isolated():
    buf = bytearray(b"k" * MIN_KEY_BYTES)
    # Deliberately pass a bytearray (outside the `bytes` contract) to prove the
    # constructor takes its own immutable copy of mutable input.
    key = HMACKey(buf)  # ty: ignore[invalid-argument-type]
    buf[0] ^= 0xFF  # mutate the original buffer
    assert key.key == b"k" * MIN_KEY_BYTES


# ---------------------------------------------------------------------------
# Ed25519PublicKey
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_public_key_must_be_32_bytes(length):
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519PublicKey(b"x" * length)


def test_public_key_bytes_returns_raw_public_key():
    raw = PAIR.public_key.public_bytes_raw()
    assert bytes(Ed25519PublicKey(raw)) == raw


def test_public_key_id_defaults_to_sha512_of_public_key():
    raw = PAIR.public_key.public_bytes_raw()
    assert Ed25519PublicKey(raw).id == default_id(raw)


def test_public_key_explicit_id_is_kept():
    raw = PAIR.public_key.public_bytes_raw()
    assert Ed25519PublicKey(raw, id="kid-1").id == "kid-1"


def test_public_key_exposes_crypto_public_key():
    pub = PAIR.public()
    assert pub.public_key.public_bytes_raw() == PAIR.public_key.public_bytes_raw()


@pytest.mark.parametrize("attr", ["key", "id"])
def test_public_key_is_frozen(attr):
    pub = PAIR.public()
    with pytest.raises(AttributeError):
        setattr(pub, attr, b"z" * 32)


# ---------------------------------------------------------------------------
# Ed25519KeyPair
# ---------------------------------------------------------------------------


def test_generate_produces_distinct_keys():
    a = Ed25519KeyPair.generate().private_key.private_bytes_raw()
    b = Ed25519KeyPair.generate().private_key.private_bytes_raw()
    assert a != b


def test_from_private_bytes_round_trips_seed():
    pair = Ed25519KeyPair.from_private_bytes(b"s" * 32)
    assert pair.private_key.private_bytes_raw() == b"s" * 32


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_private_seed_must_be_32_bytes(length):
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519KeyPair.from_private_bytes(b"x" * length)


def test_keypair_id_defaults_to_sha512_of_public_key():
    raw = PAIR.public_key.public_bytes_raw()
    assert PAIR.id == default_id(raw)


def test_keypair_explicit_id_is_kept():
    assert Ed25519KeyPair.from_private_bytes(b"s" * 32, id="kid-1").id == "kid-1"


def test_keypair_accepts_raw_private_bytes():
    pair = Ed25519KeyPair(b"s" * 32)
    assert pair.private_key.private_bytes_raw() == b"s" * 32


def test_keypair_accepts_raw_public_bytes():
    pair = Ed25519KeyPair(b"s" * 32, ED_PUBLIC)
    assert pair.public_key.public_bytes_raw() == ED_PUBLIC


def test_keypair_rejects_mismatched_public_key():
    other_public = Ed25519KeyPair.from_private_bytes(b"a" * 32).public_key
    with pytest.raises(ValueError, match="Mismatch"):
        Ed25519KeyPair(b"s" * 32, other_public)


def test_keypair_and_its_public_key_share_an_id():
    assert PAIR.id == PAIR.public().id


def test_keypair_repr_does_not_leak_the_seed():
    pair = Ed25519KeyPair.from_private_bytes(b"s" * 32, id="kid-1")
    rep = repr(pair)
    assert "kid-1" in rep
    assert (b"s" * 32).hex()[:5] not in rep  # seed must not appear
    assert pair.public_key.public_bytes_raw().hex()[:5] in rep  # public instead


# ---------------------------------------------------------------------------
# KeySet — parsing user-supplied key values
# ---------------------------------------------------------------------------


def test_accepts_raw_bytes_as_hmac():
    ks = KeySet([KEY])
    assert bytes(ks[default_id(KEY)]) == KEY


def test_raw_bytes_are_read_as_hmac_not_ed25519():
    # Raw bytes are unambiguously an HMAC key; Ed25519 keys must be wrapped.
    (key,) = KeySet([b"k" * 64])
    assert isinstance(key, HMACKey)


def test_accepts_bytes_id_tuple():
    ks = KeySet([(KEY, "kid-1")])
    assert bytes(ks["kid-1"]) == KEY


@pytest.mark.parametrize(
    "key",
    [
        HMACKey(KEY, id="hmac"),
        Ed25519KeyPair.from_private_bytes(b"s" * 32, id="pair"),
        Ed25519KeyPair.from_private_bytes(b"s" * 32, id="pub").public(),
    ],
)
def test_accepts_wrapped_keys_unchanged(key):
    (parsed,) = KeySet([key])
    assert parsed is key


@pytest.mark.parametrize(
    "bad, message",
    [
        ((("not-bytes", "kid"),), "Keys in tuples must be bytes"),
        (((KEY, 123),), "Key ids must be strings."),
        ((123,), "Invalid key value"),
        (("a-string",), "Invalid key value"),
    ],
)
def test_invalid_values_raise(bad, message):
    with pytest.raises(ValueError, match=message):
        KeySet(bad)


# ---------------------------------------------------------------------------
# KeySet — container protocol
# ---------------------------------------------------------------------------


def test_len_counts_keys():
    assert len(KeySet([kb(b"a"), kb(b"b"), kb(b"c")])) == 3


def test_getitem_by_id():
    ks = KeySet([(KEY, "kid-1")])
    assert bytes(ks["kid-1"]) == KEY


def test_getitem_missing_raises_keyerror():
    with pytest.raises(KeyError):
        KeySet([KEY])["nope"]


def test_iter_yields_values_in_order():
    ks = KeySet([(kb(b"a"), "k1"), (kb(b"b"), "k2")])
    assert [k.id for k in ks] == ["k1", "k2"]


def test_reversed_yields_values_in_reverse():
    ks = KeySet([(kb(b"a"), "k1"), (kb(b"b"), "k2")])
    assert [k.id for k in reversed(ks)] == ["k2", "k1"]


def test_duplicate_ids_raise():
    with pytest.raises(ValueError, match="Duplicate kid detected: dup"):
        KeySet([(kb(b"a"), "dup"), (kb(b"b"), "dup")])


def test_keyset_contents_are_read_only():
    ks = KeySet([KEY])
    with pytest.raises(TypeError):
        # The mapping is a read-only MappingProxyType; the static error here is
        # exactly the immutability we assert raises at runtime.
        ks._keys["x"] = HMACKey(KEY_A)  # ty: ignore[invalid-assignment]


def test_mixes_algorithms():
    ks = KeySet([HMACKey(KEY, id="hmac"), PAIR_A])
    assert len(ks) == 2
    assert isinstance(ks["hmac"], HMACKey)
    assert ks[PAIR_A.id] is PAIR_A


def test_keypair_and_matching_public_raise_on_duplicate_id():
    # Same identity -> same id -> rejected as a duplicate.
    with pytest.raises(ValueError, match="Duplicate kid detected"):
        KeySet([PAIR, PAIR.public()])


# ---------------------------------------------------------------------------
# KeySet.from_jwks
# ---------------------------------------------------------------------------


def b64u(raw: bytes) -> str:
    """base64url without padding, as JWK encodes key material (RFC 7517)."""
    return urlsafe_b64encode(raw).rstrip(b"=").decode()


ED_SEED = b"s" * 32
ED_PUBLIC = Ed25519KeyPair.from_private_bytes(ED_SEED).public_key.public_bytes_raw()
HMAC_SECRET = b"h" * 64


def ed25519_keypair_jwk(kid: str = "ed-pair") -> dict:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "x": b64u(ED_PUBLIC),
        "d": b64u(ED_SEED),
    }


def ed25519_public_jwk(kid: str = "ed-pub") -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64u(ED_PUBLIC)}


def hmac_jwk(kid: str = "hmac") -> dict:
    return {"kty": "oct", "alg": "HS512", "kid": kid, "k": b64u(HMAC_SECRET)}


def test_from_jwks_builds_ed25519_keypair():
    (key,) = KeySet.from_jwks({"keys": [ed25519_keypair_jwk()]})
    assert isinstance(key, Ed25519KeyPair)
    assert key.private_key.private_bytes_raw() == ED_SEED
    assert key.public_key.public_bytes_raw() == ED_PUBLIC


def test_from_jwks_builds_public_only_ed25519_when_d_absent():
    (key,) = KeySet.from_jwks({"keys": [ed25519_public_jwk()]})
    assert isinstance(key, Ed25519PublicKey)
    assert bytes(key) == ED_PUBLIC


def test_from_jwks_builds_hmac_key():
    (key,) = KeySet.from_jwks({"keys": [hmac_jwk()]})
    assert isinstance(key, HMACKey)
    assert bytes(key) == HMAC_SECRET


def test_from_jwks_uses_kid_as_id():
    ks = KeySet.from_jwks({"keys": [ed25519_keypair_jwk(kid="my-kid")]})
    assert ks["my-kid"].id == "my-kid"


def test_from_jwks_decodes_base64url_without_padding():
    # A public key whose raw bytes contain 0xFF/0xFE exercises the base64url
    # alphabet (-, _) and the missing-padding handling.
    raw = bytes(range(32))
    jwk = {"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": b64u(raw)}
    (key,) = KeySet.from_jwks({"keys": [jwk]})
    assert bytes(key) == raw


def test_from_jwks_builds_mixed_set():
    jwks = {"keys": [hmac_jwk("h"), ed25519_keypair_jwk("p"), ed25519_public_jwk("u")]}
    ks = KeySet.from_jwks(jwks)
    assert {k.id for k in ks} == {"h", "p", "u"}
    assert isinstance(ks["h"], HMACKey)
    assert isinstance(ks["p"], Ed25519KeyPair)
    assert isinstance(ks["u"], Ed25519PublicKey)


@pytest.mark.parametrize("jwks", [{}, {"keys": []}], ids=["missing", "empty"])
def test_from_jwks_without_keys_raises(jwks):
    with pytest.raises(ValueError, match="No 'keys'"):
        KeySet.from_jwks(jwks)


def test_from_jwks_unsupported_key_type_raises():
    jwks = {"keys": [{"kty": "RSA", "kid": "rsa", "n": "...", "e": "AQAB"}]}
    with pytest.raises(NotImplementedError, match="Unknown key type"):
        KeySet.from_jwks(jwks)


# ---------------------------------------------------------------------------
# KeySet.from_env
# ---------------------------------------------------------------------------

ENV_VAR = "PYSIGNED_TEST_KEYS"


def test_from_env_builds_keyset_from_json_jwks(monkeypatch):
    jwks = json.dumps({"keys": [hmac_jwk()]})
    monkeypatch.setenv(ENV_VAR, jwks)
    (key,) = KeySet.from_env(ENV_VAR)
    assert isinstance(key, HMACKey)
    assert bytes(key) == HMAC_SECRET


def test_from_env_passes_backend_through(monkeypatch):
    jwks = json.dumps({"keys": [hmac_jwk()]})
    monkeypatch.setenv(ENV_VAR, jwks)
    backend = Backend()
    ks = KeySet.from_env(ENV_VAR, backend=backend)
    assert ks.backend is backend


def test_from_env_unset_raises(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    with pytest.raises(ValueError, match=f"{ENV_VAR} unset"):
        KeySet.from_env(ENV_VAR)


def test_from_env_empty_raises(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "")
    with pytest.raises(ValueError, match=f"{ENV_VAR} unset"):
        KeySet.from_env(ENV_VAR)


def test_from_env_invalid_json_raises(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "not json")
    with pytest.raises(json.JSONDecodeError):
        KeySet.from_env(ENV_VAR)


# ---------------------------------------------------------------------------
# KeySet.from_url
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal stand-in for an ``http.client.HTTPResponse``.

    Supports the context-manager + ``.read()`` interface that ``from_url``
    uses, returning a fixed body as raw bytes.
    """

    def __init__(self, body: str):
        self._body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._body


def fake_urlopen(monkeypatch, body: str):
    """Patch ``pysigned.keys.urlopen`` to return ``body``, capturing the request.

    Returns a list that the patched ``urlopen`` appends each received
    ``Request`` to, so tests can assert on the URL and headers sent.
    """
    requests = []

    def _urlopen(request):
        requests.append(request)
        return _FakeResponse(body)

    monkeypatch.setattr("pysigned.keys.urlopen", _urlopen)
    return requests


def test_from_url_builds_keyset_from_fetched_jwks(monkeypatch):
    body = json.dumps({"keys": [hmac_jwk()]})
    fake_urlopen(monkeypatch, body)
    (key,) = KeySet.from_url("https://issuer.example/jwks.json")
    assert isinstance(key, HMACKey)
    assert bytes(key) == HMAC_SECRET


def test_from_url_builds_mixed_set(monkeypatch):
    body = json.dumps(
        {"keys": [hmac_jwk("h"), ed25519_keypair_jwk("p"), ed25519_public_jwk("u")]}
    )
    fake_urlopen(monkeypatch, body)
    ks = KeySet.from_url("https://issuer.example/jwks.json")
    assert {k.id for k in ks} == {"h", "p", "u"}


def test_from_url_requests_the_given_url(monkeypatch):
    requests = fake_urlopen(monkeypatch, json.dumps({"keys": [hmac_jwk()]}))
    KeySet.from_url("https://issuer.example/jwks.json")
    assert requests[0].full_url == "https://issuer.example/jwks.json"


def test_from_url_sends_user_agent_and_accept_headers(monkeypatch):
    requests = fake_urlopen(monkeypatch, json.dumps({"keys": [hmac_jwk()]}))
    KeySet.from_url("https://issuer.example/jwks.json")
    # urllib title-cases header keys.
    headers = requests[0].headers
    assert headers["User-agent"] == f"Pysigned/{__version__}"
    assert headers["Accept"] == "application/json"


def test_from_url_passes_backend_through(monkeypatch):
    fake_urlopen(monkeypatch, json.dumps({"keys": [hmac_jwk()]}))
    backend = Backend()
    ks = KeySet.from_url("https://issuer.example/jwks.json", backend=backend)
    assert ks.backend is backend


def test_from_url_without_keys_raises(monkeypatch):
    fake_urlopen(monkeypatch, json.dumps({}))
    with pytest.raises(ValueError, match="No 'keys'"):
        KeySet.from_url("https://issuer.example/jwks.json")


def test_from_url_invalid_json_raises(monkeypatch):
    fake_urlopen(monkeypatch, "not json")
    with pytest.raises(json.JSONDecodeError):
        KeySet.from_url("https://issuer.example/jwks.json")


@pytest.fixture
def jwks_server():
    """Serve a JWKS over a real loopback HTTP server for the test's duration.

    Yields ``(base_url, captured)`` where ``captured`` records the path and
    request headers of each request, so the test exercises the genuine
    ``urllib`` request/response path (not a monkeypatched ``urlopen``).
    """
    body = json.dumps(
        {"keys": [hmac_jwk("h"), ed25519_keypair_jwk("p"), ed25519_public_jwk("u")]}
    ).encode("utf-8")
    captured: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            captured.append({"path": self.path, "headers": dict(self.headers)})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # keep pytest output clean

    class _Server(HTTPServer):
        # HTTPServer.server_bind() calls socket.getfqdn(), a reverse-DNS lookup
        # that can hang for tens of seconds; we don't need the FQDN here.
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name = "127.0.0.1"
            self.server_port = self.server_address[1]

    server = _Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", captured
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_from_url_against_real_server(jwks_server):
    base_url, captured = jwks_server
    ks = KeySet.from_url(f"{base_url}/jwks.json")

    assert {k.id for k in ks} == {"h", "p", "u"}
    assert isinstance(ks["h"], HMACKey)
    assert isinstance(ks["p"], Ed25519KeyPair)
    assert isinstance(ks["u"], Ed25519PublicKey)

    # The real request carried the path and headers from_url builds.
    (request,) = captured
    assert request["path"] == "/jwks.json"
    assert request["headers"]["User-Agent"] == f"Pysigned/{__version__}"
    assert request["headers"]["Accept"] == "application/json"
