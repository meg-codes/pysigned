"""Tests for URLAuth: signing, verification, rotation, and options.

Each behaviour is exercised against HMAC and Ed25519 keysets where the two
should behave identically, and there are dedicated sections for the asymmetric
guarantees (public-only verification, public keys cannot sign) and for keysets
that mix the two algorithms.
"""

from time import time
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

import pytest

from pysigned import (
    Backend,
    Ed25519KeyPair,
    HMACKey,
    KeySet,
    URLAuth,
)
from pysigned.keys import MIN_KEY_BYTES


def kb(seed: bytes) -> bytes:
    """A valid (>= MIN_KEY_BYTES) HMAC key derived from a short seed."""
    return (seed * MIN_KEY_BYTES)[:MIN_KEY_BYTES]


# HMAC and Ed25519 keysets that should behave identically under URLAuth. Each
# factory returns a fresh KeySet so tests stay independent.
def hmac_keys() -> KeySet:
    return KeySet([kb(b"k")])


def ed25519_keys() -> KeySet:
    return KeySet([Ed25519KeyPair.from_private_bytes(b"s" * 32)])


both_algorithms = pytest.mark.parametrize(
    "keys", [hmac_keys, ed25519_keys], ids=["hmac", "ed25519"]
)


# ---------------------------------------------------------------------------
# URLAuth construction
# ---------------------------------------------------------------------------


def test_accepts_raw_values_and_wraps_them():
    signer = URLAuth([kb(b"k")])
    assert isinstance(signer.keys, KeySet)


def test_accepts_prebuilt_keyset_without_rewrapping():
    ks = KeySet([kb(b"k")])
    assert URLAuth(ks).keys is ks


def test_signer_uses_backend_from_keyset():
    assert isinstance(URLAuth(ed25519_keys()).backend, Backend)


def test_signing_key_defaults_to_most_recently_added():
    signer = URLAuth([(kb(b"a"), "old"), (kb(b"b"), "new")])
    assert signer.signing_key_id == "new"


def test_explicit_signing_key_id_is_respected():
    signer = URLAuth([(kb(b"a"), "old"), (kb(b"b"), "new")], signing_key_id="old")
    assert signer.signing_key_id == "old"


# ---------------------------------------------------------------------------
# sign / verify round trip
# ---------------------------------------------------------------------------


@both_algorithms
def test_sign_appends_sig_and_exp(keys):
    signer = URLAuth(keys())
    signed = signer.sign("https://example.com/a?b=1")
    query = parse_qs(urlparse(signed).query)
    assert "sig" in query and "exp" in query
    assert query["b"] == ["1"]  # original params preserved


@both_algorithms
def test_sign_then_verify_succeeds(keys):
    signer = URLAuth(keys())
    assert signer.verify(signer.sign("https://example.com/a?b=1")) is True


@both_algorithms
def test_round_trips_query_that_does_not_re_encode_identically(keys):
    # Spaces and repeated keys don't survive a raw round trip; sign() and
    # verify() must canonicalise the query the same way.
    signer = URLAuth(keys())
    signed = signer.sign("https://example.com/p?q=hello world&a=1&a=2")
    assert signer.verify(signed) is True


@both_algorithms
def test_verify_survives_reordered_query_params(keys):
    # Canonical signing must not depend on query-param order: a verifier that
    # receives the same params in a different order still verifies.
    signer = URLAuth(keys())
    signed = signer.sign("https://example.com/p?a=1&b=2&c=3")

    parsed = urlparse(signed)
    reordered_query = urlencode(list(reversed(parse_qsl(parsed.query))))
    reordered = parsed._replace(query=reordered_query).geturl()

    assert reordered != signed  # the order really did change
    assert signer.verify(reordered) is True


@both_algorithms
@pytest.mark.parametrize(
    "tamper",
    [
        lambda u: u.replace("b=1", "b=2"),  # changed query value
        lambda u: u.replace("/a?", "/evil?"),  # changed path
        lambda u: u.replace("https://", "http://"),  # changed scheme
    ],
)
def test_verify_rejects_tampered_url(keys, tamper):
    signer = URLAuth(keys())
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(tamper(signed)) is False


@both_algorithms
@pytest.mark.parametrize(
    "query",
    [
        "sig=deadbeef",  # missing exp
        "exp=9999999999",  # missing sig
        "sig=deadbeef&exp=notanint",  # non-integer exp
        "sig=nothex&exp=9999999999",  # malformed signature
        "",  # neither
    ],
)
def test_verify_rejects_missing_or_malformed_params(keys, query):
    signer = URLAuth(keys())
    assert signer.verify(f"https://example.com/?{query}") is False


# ---------------------------------------------------------------------------
# Expiry, ttl, and clock skew
# ---------------------------------------------------------------------------


def test_sign_uses_configured_ttl():
    signer = URLAuth([kb(b"k")], ttl=100)
    signed = signer.sign("https://example.com/")
    exp = int(parse_qs(urlparse(signed).query)["exp"][0])
    assert abs(exp - (int(time()) + 100)) <= 2


def test_verify_rejects_expired_signature():
    signer = URLAuth([kb(b"k")], ttl=-100)  # already expired on creation
    assert signer.verify(signer.sign("https://example.com/")) is False


def test_skew_allows_recently_expired_signature():
    signer = URLAuth([kb(b"k")], ttl=-100)
    signed = signer.sign("https://example.com/")
    assert signer.verify(signed, skew=0) is False
    assert signer.verify(signed, skew=200) is True


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------


def test_verify_accepts_rotated_out_hmac_key():
    old = URLAuth([(kb(b"a"), "old")])
    signed = old.sign("https://example.com/")
    rotated = URLAuth([(kb(b"a"), "old"), (kb(b"b"), "new")])
    assert rotated.verify(signed) is True
    assert rotated.signing_key_id == "new"  # but new signatures use the new key


def test_verify_accepts_rotated_out_ed25519_key():
    a = Ed25519KeyPair.from_private_bytes(b"a" * 32, id="old")
    b = Ed25519KeyPair.from_private_bytes(b"b" * 32, id="new")
    signed = URLAuth(KeySet([a])).sign("https://example.com/")
    rotated = URLAuth(KeySet([a, b]))
    assert rotated.verify(signed) is True
    assert rotated.signing_key_id == "new"


def test_verify_rejects_signature_from_unknown_key():
    signed = URLAuth([(kb(b"a"), "a")]).sign("https://example.com/")
    assert URLAuth([(kb(b"b"), "b")]).verify(signed) is False


# ---------------------------------------------------------------------------
# Asymmetric guarantees: public-only verification, public keys cannot sign
# ---------------------------------------------------------------------------


def test_sign_with_keypair_verify_with_public_only():
    pair = Ed25519KeyPair.generate()
    signed = URLAuth(KeySet([pair])).sign("https://example.com/a?b=1")

    # Verifier side holds only the public key -- no secret.
    verifier = URLAuth(KeySet([pair.public()]))
    assert verifier.verify(signed) is True


def test_verify_rejects_ed25519_signature_from_unknown_key():
    signed = URLAuth(KeySet([Ed25519KeyPair.from_private_bytes(b"a" * 32)])).sign(
        "https://example.com/"
    )
    other = Ed25519KeyPair.from_private_bytes(b"b" * 32).public()
    assert URLAuth(KeySet([other])).verify(signed) is False


def test_signing_with_public_only_keyset_raises():
    signer = URLAuth(KeySet([Ed25519KeyPair.from_private_bytes(b"s" * 32).public()]))
    with pytest.raises(TypeError, match="public keys cannot sign"):
        signer.sign("https://example.com/")


# ---------------------------------------------------------------------------
# Mixing algorithms in one keyset
# ---------------------------------------------------------------------------


HMAC_KEY = HMACKey(kb(b"h"), id="hmac")
ED_PAIR = Ed25519KeyPair.from_private_bytes(b"s" * 32, id="ed")


@pytest.mark.parametrize("signing_key_id", ["hmac", "ed"])
def test_sign_with_either_algorithm_then_verify(signing_key_id):
    signer = URLAuth(KeySet([HMAC_KEY, ED_PAIR]), signing_key_id=signing_key_id)
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(signed) is True


@pytest.mark.parametrize("signing_key_id", ["hmac", "ed"])
def test_tampering_rejected_for_either_algorithm(signing_key_id):
    signer = URLAuth(KeySet([HMAC_KEY, ED_PAIR]), signing_key_id=signing_key_id)
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(signed.replace("b=1", "b=2")) is False


def test_mixed_set_accepts_signature_from_rotated_out_algorithm():
    # Signed with HMAC, then the audience migrated to also accept Ed25519.
    signed = URLAuth(KeySet([HMAC_KEY])).sign("https://example.com/")
    mixed = URLAuth(KeySet([HMAC_KEY, ED_PAIR]), signing_key_id="ed")
    assert mixed.verify(signed) is True


def test_public_only_ed25519_in_mixed_set_cannot_be_default_signer():
    # Last-added key is a public Ed25519 key, which cannot sign.
    signer = URLAuth(KeySet([HMAC_KEY, ED_PAIR.public()]))
    with pytest.raises(TypeError, match="public keys cannot sign"):
        signer.sign("https://example.com/")
    # ...but an explicit HMAC signing key works.
    signer = URLAuth(KeySet([HMAC_KEY, ED_PAIR.public()]), signing_key_id="hmac")
    assert signer.verify(signer.sign("https://example.com/")) is True


# ---------------------------------------------------------------------------
# require_kid: signer pins verification to the single key named by `kid`
# ---------------------------------------------------------------------------


@both_algorithms
def test_require_kid_signs_with_kid_of_signing_key(keys):
    signer = URLAuth(keys(), require_kid=True)
    signed = signer.sign("https://example.com/")
    assert parse_qs(urlparse(signed).query)["kid"] == [signer.signing_key_id]


@both_algorithms
def test_default_does_not_emit_kid(keys):
    signer = URLAuth(keys())
    signed = signer.sign("https://example.com/")
    assert "kid" not in parse_qs(urlparse(signed).query)


@both_algorithms
def test_require_kid_round_trips(keys):
    signer = URLAuth(keys(), require_kid=True)
    assert signer.verify(signer.sign("https://example.com/a?b=1")) is True


def test_require_kid_rejects_url_without_kid():
    # A require_kid signer will not fall back to scanning the keyset.
    signer = URLAuth([(kb(b"a"), "a")], require_kid=True)
    unsigned_kid = URLAuth([(kb(b"a"), "a")]).sign("https://example.com/")
    assert "kid" not in parse_qs(urlparse(unsigned_kid).query)
    assert signer.verify(unsigned_kid) is False


def test_require_kid_pointing_at_unknown_key_rejected():
    signer = URLAuth([(kb(b"a"), "a")], require_kid=True)
    signed = signer.sign("https://example.com/")
    assert signer.verify(signed.replace("kid=a", "kid=nope")) is False


def test_require_kid_restricts_verification_to_the_named_key_alone():
    # The signature is made by "new", but the URL is rewritten to claim kid=old.
    # Even though the keyset still holds "new" (which a full scan would accept),
    # pinning to "old" alone must reject it.
    full = URLAuth([(kb(b"a"), "old"), (kb(b"b"), "new")], require_kid=True)
    signed = full.sign("https://example.com/")  # signed by "new", kid=new
    forged = signed.replace("kid=new", "kid=old")
    assert full.verify(forged) is False
    # Sanity: untouched, it verifies.
    assert full.verify(signed) is True


def test_kid_is_not_part_of_the_signed_message():
    # kid is excluded from the canonical message, so changing its *value* cannot
    # itself break the signature -- it only redirects which key is consulted.
    signer = URLAuth([(kb(b"a"), "real")], require_kid=True)
    signed = signer.sign("https://example.com/")
    # Redirected to a missing key: only that key is tried, so verification fails
    # even though the signature is otherwise valid.
    assert signer.verify(signed.replace("kid=real", "kid=ghost")) is False


def test_kid_ignored_when_not_required():
    # Without require_kid, a stray kid in the URL is ignored: verification still
    # scans the whole set, so even a bogus kid value verifies.
    signer = URLAuth([(kb(b"a"), "a")])
    signed = signer.sign("https://example.com/")
    assert signer.verify(signed + "&kid=bogus") is True


def test_require_kid_pins_to_correct_key_in_mixed_set():
    # Signed with the Ed25519 key; verification succeeds by checking only that
    # key, not by scanning the HMAC key too.
    signer = URLAuth(KeySet([HMAC_KEY, ED_PAIR]), signing_key_id="ed", require_kid=True)
    signed = signer.sign("https://example.com/a?b=1")
    assert parse_qs(urlparse(signed).query)["kid"] == ["ed"]
    assert signer.verify(signed) is True


def test_require_kid_url_with_tampered_path_is_rejected():
    signer = URLAuth([(kb(b"k"), "k")], require_kid=True)
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(signed.replace("b=1", "b=2")) is False


# ---------------------------------------------------------------------------
# ignore_query_params
# ---------------------------------------------------------------------------


def test_signed_url_still_contains_ignored_param():
    # Ignored params are excluded from the signature, not stripped from the URL.
    signer = URLAuth([kb(b"k")], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1&utm=x")
    assert parse_qs(urlparse(signed).query)["utm"] == ["x"]


def test_changing_ignored_param_value_still_verifies():
    signer = URLAuth([kb(b"k")], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1&utm=before")
    assert signer.verify(signed.replace("utm=before", "utm=after")) is True


def test_adding_ignored_param_still_verifies():
    signer = URLAuth([kb(b"k")], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1")
    assert signer.verify(signed + "&utm=added") is True


def test_removing_ignored_param_still_verifies():
    signer = URLAuth([kb(b"k")], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?utm=x&a=1")
    assert signer.verify(signed.replace("utm=x&", "")) is True


def test_non_ignored_param_is_still_protected():
    signer = URLAuth([kb(b"k")], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1&utm=x")
    assert signer.verify(signed.replace("a=1", "a=2")) is False


def test_multiple_ignored_params():
    signer = URLAuth([kb(b"k")], ignore_query_params=["utm_source", "utm_medium"])
    signed = signer.sign("https://example.com/p?a=1&utm_source=s&utm_medium=m")
    tampered = signed.replace("utm_source=s", "utm_source=x").replace(
        "utm_medium=m", "utm_medium=y"
    )
    assert signer.verify(tampered) is True


def test_ignore_list_accepts_any_iterable():
    # A set is a valid Iterable[str]; order-independence is fine since the
    # list is only used for membership tests.
    signer = URLAuth([kb(b"k")], ignore_query_params={"utm"})
    signed = signer.sign("https://example.com/p?a=1&utm=x")
    assert signer.verify(signed.replace("utm=x", "utm=y")) is True


def test_default_signs_every_param():
    # Without an ignore list, any query param is protected.
    signer = URLAuth([kb(b"k")])
    signed = signer.sign("https://example.com/p?utm=x")
    assert signer.verify(signed.replace("utm=x", "utm=y")) is False


def test_one_shot_iterable_ignore_list_is_not_exhausted():
    # A generator must survive being used across both sign() and verify(),
    # and across repeated calls.
    signer = URLAuth([kb(b"k")], ignore_query_params=(p for p in ["utm"]))
    signed = signer.sign("https://example.com/p?a=1&utm=x")  # sign uses it
    assert signer.verify(signed.replace("utm=x", "utm=y")) is True  # verify too
    assert signer.verify(signed.replace("utm=x", "utm=z")) is True  # still works
