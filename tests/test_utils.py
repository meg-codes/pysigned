"""Tests for the key-generation helpers and pysigned-gen-key CLI."""

import hashlib
import json
from base64 import urlsafe_b64decode, urlsafe_b64encode

import pytest

from pysigned.utils import gen_key, jwk_ed25519, jwk_hmac


def b64u_decode(s: str) -> bytes:
    padding_needed = -len(s) % 4
    return urlsafe_b64decode(s + ("=" * padding_needed))


def expected_kid(material: bytes) -> str:
    """The kid format: base64url of SHA-512(material), truncated to 12 chars."""
    return urlsafe_b64encode(hashlib.sha512(material).digest()).decode()[:12]


# ---------------------------------------------------------------------------
# jwk_hmac
# ---------------------------------------------------------------------------


def test_jwk_hmac_shape():
    jwk = jwk_hmac()
    assert jwk["kty"] == "oct"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "HS512"


def test_jwk_hmac_key_is_64_bytes():
    jwk = jwk_hmac()
    assert len(b64u_decode(jwk["k"])) == 64


def test_jwk_hmac_kid_is_sha512_of_key():
    jwk = jwk_hmac()
    key = b64u_decode(jwk["k"])
    assert jwk["kid"] == expected_kid(key)


def test_jwk_hmac_distinct_each_call():
    assert jwk_hmac()["k"] != jwk_hmac()["k"]


# ---------------------------------------------------------------------------
# jwk_ed25519
# ---------------------------------------------------------------------------


def test_jwk_ed25519_shape():
    jwk = jwk_ed25519()
    assert jwk["kty"] == "OKP"
    assert jwk["use"] == "sig"
    assert jwk["crv"] == "Ed25519"


def test_jwk_ed25519_keys_are_32_bytes():
    jwk = jwk_ed25519()
    assert len(b64u_decode(jwk["x"])) == 32
    assert len(b64u_decode(jwk["d"])) == 32


def test_jwk_ed25519_kid_is_sha512_of_public_key():
    jwk = jwk_ed25519()
    public = b64u_decode(jwk["x"])
    assert jwk["kid"] == expected_kid(public)


def test_jwk_ed25519_x_matches_d():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    jwk = jwk_ed25519()
    private = ed25519.Ed25519PrivateKey.from_private_bytes(b64u_decode(jwk["d"]))
    assert private.public_key().public_bytes_raw() == b64u_decode(jwk["x"])


def test_jwk_ed25519_distinct_each_call():
    assert jwk_ed25519()["d"] != jwk_ed25519()["d"]


# ---------------------------------------------------------------------------
# gen_key (CLI entry point)
# ---------------------------------------------------------------------------


def run_gen_key(monkeypatch, capsys, *args):
    monkeypatch.setattr("sys.argv", ["pysigned-gen-key", *args])
    gen_key()
    return capsys.readouterr().out


def test_gen_key_requires_hmac_or_ed25519(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["pysigned-gen-key"])
    with pytest.raises(SystemExit):
        gen_key()


def test_gen_key_rejects_both_hmac_and_ed25519(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["pysigned-gen-key", "--hmac", "--ed25519"])
    with pytest.raises(SystemExit):
        gen_key()


def test_gen_key_hmac_prints_jwk(monkeypatch, capsys):
    out = run_gen_key(monkeypatch, capsys, "--hmac")
    assert json.loads(out)["kty"] == "oct"


def test_gen_key_ed25519_prints_jwk(monkeypatch, capsys):
    out = run_gen_key(monkeypatch, capsys, "--ed25519")
    assert json.loads(out)["kty"] == "OKP"


def test_gen_key_jwks_wraps_key_in_keys_list(monkeypatch, capsys):
    out = run_gen_key(monkeypatch, capsys, "--hmac", "--jwks")
    parsed = json.loads(out)
    assert list(parsed) == ["keys"]
    assert parsed["keys"][0]["kty"] == "oct"


def test_gen_key_default_output_is_indented(monkeypatch, capsys):
    out = run_gen_key(monkeypatch, capsys, "--hmac")
    assert "\n" in out


def test_gen_key_compact_output_has_no_whitespace(monkeypatch, capsys):
    out = run_gen_key(monkeypatch, capsys, "--hmac", "--compact")
    assert out.strip().count("\n") == 0
    assert ", " not in out and ": " not in out


def test_gen_key_compact_is_still_valid_json(monkeypatch, capsys):
    out = run_gen_key(monkeypatch, capsys, "--ed25519", "--jwks", "--compact")
    parsed = json.loads(out)
    assert parsed["keys"][0]["crv"] == "Ed25519"
