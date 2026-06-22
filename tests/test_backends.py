"""Tests for Backend: key parsing and algorithm dispatch on sign/verify."""

import hmac
from dataclasses import dataclass

import pytest

from pysigned.backends import Backend
from pysigned.keys import (
    DIGEST,
    MIN_KEY_BYTES,
    Ed25519KeyPair,
    HMACKey,
    Key,
)

KEY = (b"k" * MIN_KEY_BYTES)
PAIR = Ed25519KeyPair.from_private_bytes(b"s" * 32)


# ---------------------------------------------------------------------------
# parse_key
# ---------------------------------------------------------------------------


def test_parse_wraps_raw_bytes_as_hmac():
    assert isinstance(Backend().parse_key(KEY), HMACKey)


def test_parse_wraps_bytes_id_tuple_as_hmac():
    key = Backend().parse_key((KEY, "kid-1"))
    assert isinstance(key, HMACKey)
    assert key.id == "kid-1"


@pytest.mark.parametrize("key", [HMACKey(KEY), PAIR, PAIR.public()])
def test_parse_passes_wrapped_keys_through(key):
    assert Backend().parse_key(key) is key


@pytest.mark.parametrize(
    "bad, message",
    [
        (("not-bytes", "kid"), "Keys in tuples must be bytes"),
        ((KEY, 123), "Key ids must be strings."),
        (123, "Invalid key value"),
        ("a-string", "Invalid key value"),
    ],
)
def test_parse_rejects_invalid_values(bad, message):
    with pytest.raises(ValueError, match=message):
        Backend().parse_key(bad)


# ---------------------------------------------------------------------------
# sign — dispatches on key type
# ---------------------------------------------------------------------------


def test_sign_hmac_matches_stdlib_hmac():
    backend = Backend()
    expected = hmac.new(KEY, b"msg", DIGEST).hexdigest()
    assert backend.sign(HMACKey(KEY), b"msg") == expected


def test_sign_with_keypair_verifies_with_its_public_key():
    sig = Backend().sign(PAIR, b"msg")
    PAIR.public_key.verify(bytes.fromhex(sig), b"msg")  # raises if invalid


@pytest.mark.parametrize("key", [PAIR.public(), object()])
def test_sign_with_non_signing_key_raises(key):
    with pytest.raises(TypeError, match="public keys cannot sign"):
        Backend().sign(key, b"msg")


# ---------------------------------------------------------------------------
# verify — dispatches on key type
# ---------------------------------------------------------------------------


def test_verify_hmac_round_trip():
    backend = Backend()
    sig = backend.sign(HMACKey(KEY), b"msg")
    assert backend.verify(HMACKey(KEY), b"msg", sig) is True


def test_verify_hmac_rejects_bad_signature():
    assert Backend().verify(HMACKey(KEY), b"msg", "aabbcc") is False


@pytest.mark.parametrize("verifier", [PAIR, PAIR.public()])
def test_verify_ed25519_round_trip(verifier):
    sig = Backend().sign(PAIR, b"msg")
    assert Backend().verify(verifier, b"msg", sig) is True


def test_verify_ed25519_rejects_tampered_message():
    sig = Backend().sign(PAIR, b"msg")
    assert Backend().verify(PAIR.public(), b"other", sig) is False


def test_verify_ed25519_rejects_non_hex_signature():
    assert Backend().verify(PAIR.public(), b"msg", "nothex") is False


def test_verify_returns_false_for_unsupported_key_type():
    @dataclass(frozen=True, eq=False, repr=False)
    class _OtherKey(Key):
        def _validate(self):
            pass

        def _id_bytes(self):
            return self.key

    assert Backend().verify(_OtherKey(KEY), b"msg", "aabbcc") is False


# ---------------------------------------------------------------------------
# No cross-algorithm false positives
# ---------------------------------------------------------------------------


def test_hmac_signature_does_not_verify_as_ed25519():
    sig = Backend().sign(HMACKey(KEY), b"msg")
    assert Backend().verify(PAIR.public(), b"msg", sig) is False


def test_ed25519_signature_does_not_verify_as_hmac():
    sig = Backend().sign(PAIR, b"msg")
    assert Backend().verify(HMACKey(KEY), b"msg", sig) is False
