"""A single KeySet / URLAuth holding both HMAC and Ed25519 keys."""

import pytest

from pysigned import (
    Ed25519PrivateKey,
    HMACKey,
    KeySet,
    URLAuth,
)


HMAC_KEY = HMACKey(b"h" * 64, id="hmac")
ED_KEY = Ed25519PrivateKey(b"s" * 32, id="ed")


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_keyset_mixes_algorithms():
    ks = KeySet([HMAC_KEY, ED_KEY])
    assert len(ks) == 2
    assert ks["hmac"] is HMAC_KEY
    assert ks["ed"] is ED_KEY


def test_bytes_and_wrapped_ed25519_coexist():
    # Raw bytes -> HMAC, alongside a wrapped Ed25519 key.
    ks = KeySet([b"h" * 64, ED_KEY])
    kinds = {type(k) for k in ks}
    assert kinds == {HMACKey, Ed25519PrivateKey}


# ---------------------------------------------------------------------------
# Each key signs and verifies with its own algorithm
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("signing_key_id", ["hmac", "ed"])
def test_sign_with_either_key_then_verify(signing_key_id):
    signer = URLAuth(KeySet([HMAC_KEY, ED_KEY]), signing_key_id=signing_key_id)
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(signed) is True


@pytest.mark.parametrize("signing_key_id", ["hmac", "ed"])
def test_tampering_rejected_for_either_key(signing_key_id):
    signer = URLAuth(KeySet([HMAC_KEY, ED_KEY]), signing_key_id=signing_key_id)
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(signed.replace("b=1", "b=2")) is False


# ---------------------------------------------------------------------------
# No cross-algorithm false positives
# ---------------------------------------------------------------------------


def test_hmac_signature_does_not_verify_against_ed25519_only_set():
    signed = URLAuth(KeySet([HMAC_KEY])).sign("https://example.com/")
    assert URLAuth(KeySet([ED_KEY.public_key()])).verify(signed) is False


def test_ed25519_signature_does_not_verify_against_hmac_only_set():
    signed = URLAuth(KeySet([ED_KEY])).sign("https://example.com/")
    assert URLAuth(KeySet([HMAC_KEY])).verify(signed) is False


# ---------------------------------------------------------------------------
# Rotation across algorithms
# ---------------------------------------------------------------------------


def test_verify_accepts_signature_from_rotated_out_algorithm():
    # Signed with HMAC, then the audience migrated to also accept Ed25519.
    signed = URLAuth(KeySet([HMAC_KEY])).sign("https://example.com/")
    mixed = URLAuth(KeySet([HMAC_KEY, ED_KEY]), signing_key_id="ed")
    assert mixed.verify(signed) is True


def test_public_only_ed25519_in_mixed_set_cannot_be_default_signer():
    # Last-added key is a public Ed25519 key, which cannot sign.
    signer = URLAuth(KeySet([HMAC_KEY, ED_KEY.public_key()]))
    with pytest.raises(TypeError, match="public keys cannot sign"):
        signer.sign("https://example.com/")
    # ...but an explicit HMAC signing key works.
    signer = URLAuth(KeySet([HMAC_KEY, ED_KEY.public_key()]), signing_key_id="hmac")
    assert signer.verify(signer.sign("https://example.com/")) is True
