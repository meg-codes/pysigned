import hashlib
from time import time
from urllib.parse import parse_qs, urlparse

import pytest

from pysigned.signature import MIN_KEY_BYTES, HMACKey, HMACKeySet, Signer


def kb(seed: bytes) -> bytes:
    """A valid (>= MIN_KEY_BYTES) key derived from a short seed.

    HMAC-SHA512 requires keys of at least 64 bytes; this lets tests keep using
    short readable labels while still satisfying the length requirement.
    Distinct seeds yield distinct keys.
    """
    return (seed * MIN_KEY_BYTES)[:MIN_KEY_BYTES]


KEY = kb(b"k")
KEY_A = kb(b"a")
KEY_B = kb(b"b")


# ---------------------------------------------------------------------------
# HMACKey
# ---------------------------------------------------------------------------


def test_id_defaults_to_sha256_of_key():
    assert HMACKey(KEY).id == hashlib.sha256(KEY).hexdigest()


def test_explicit_id_is_kept():
    assert HMACKey(KEY, id="kid-1").id == "kid-1"


def test_bytes_returns_raw_key():
    assert bytes(HMACKey(KEY)) == KEY


def test_equal_keys_hash_equal():
    assert hash(HMACKey(KEY)) == hash(HMACKey(KEY, id="other"))


@pytest.mark.parametrize(
    "other, expected",
    [
        (HMACKey(KEY, id="different-id"), True),  # same key, different id
        (HMACKey(KEY_A), False),                  # different key
        (KEY, True),                              # raw bytes equal
        (KEY_A, False),                           # raw bytes unequal
        (object(), False),                        # unrelated object (sentinel)
        (None, False),                            # no .key attribute
    ],
)
def test_equality(other, expected):
    assert (HMACKey(KEY) == other) is expected


def test_repr_shows_id_and_truncated_key():
    rep = repr(HMACKey(KEY, id="kid-1"))
    assert "kid-1" in rep
    assert KEY.hex()[:5] in rep


# ---------------------------------------------------------------------------
# HMACKey key-length enforcement
# ---------------------------------------------------------------------------


def test_min_key_bytes_matches_sha512_output():
    assert MIN_KEY_BYTES == 64


@pytest.mark.parametrize("length", [0, 1, 63])
def test_rejects_keys_shorter_than_digest_output(length):
    with pytest.raises(ValueError, match="at least 64 bytes"):
        HMACKey(b"x" * length)


@pytest.mark.parametrize("length", [64, 80, 128])
def test_accepts_keys_at_or_above_digest_output(length):
    # 64 is the minimum for sha512; longer keys are allowed, not just 64.
    assert len(bytes(HMACKey(b"x" * length))) == length


def test_short_key_rejected_when_building_a_keyset():
    with pytest.raises(ValueError, match="at least 64 bytes"):
        HMACKeySet([b"too-short"])


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attr", ["key", "id"])
def test_hmackey_is_frozen(attr):
    key = HMACKey(KEY)
    with pytest.raises(AttributeError):
        setattr(key, attr, KEY_A)


def test_hmackey_copies_key_so_source_mutation_is_isolated():
    buf = bytearray(b"k" * MIN_KEY_BYTES)
    key = HMACKey(buf)
    buf[0] ^= 0xFF  # mutate the original buffer
    assert key.key == b"k" * MIN_KEY_BYTES


def test_keyset_contents_are_read_only():
    ks = HMACKeySet([KEY])
    with pytest.raises(TypeError):
        ks._keys["x"] = HMACKey(KEY_A)


# ---------------------------------------------------------------------------
# HMACKeySet construction / _parse_value
# ---------------------------------------------------------------------------


def test_accepts_raw_bytes():
    ks = HMACKeySet([KEY])
    assert ks[hashlib.sha256(KEY).hexdigest()].key == KEY


def test_accepts_existing_hmackey_unchanged():
    key = HMACKey(KEY, id="kid-1")
    ks = HMACKeySet([key])
    assert ks["kid-1"] is key


def test_accepts_bytes_id_tuple():
    ks = HMACKeySet([(KEY, "kid-1")])
    assert ks["kid-1"].key == KEY


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
        HMACKeySet(bad)


# ---------------------------------------------------------------------------
# HMACKeySet container protocol
# ---------------------------------------------------------------------------


def test_len_counts_keys():
    assert len(HMACKeySet([kb(b"a"), kb(b"b"), kb(b"c")])) == 3


def test_getitem_by_id():
    ks = HMACKeySet([(KEY, "kid-1")])
    assert bytes(ks["kid-1"]) == KEY


def test_getitem_missing_raises_keyerror():
    with pytest.raises(KeyError):
        HMACKeySet([KEY])["nope"]


def test_iter_yields_hmackey_values_in_order():
    ks = HMACKeySet([(kb(b"a"), "k1"), (kb(b"b"), "k2")])
    assert [k.id for k in ks] == ["k1", "k2"]


def test_reversed_yields_values_in_reverse():
    ks = HMACKeySet([(kb(b"a"), "k1"), (kb(b"b"), "k2")])
    assert [k.id for k in reversed(ks)] == ["k2", "k1"]


def test_duplicate_ids_collapse_to_last():
    ks = HMACKeySet([(kb(b"a"), "dup"), (kb(b"b"), "dup")])
    assert len(ks) == 1
    assert ks["dup"].key == kb(b"b")


# ---------------------------------------------------------------------------
# Signer construction
# ---------------------------------------------------------------------------


def test_accepts_raw_values():
    signer = Signer([KEY])
    assert isinstance(signer.keys, HMACKeySet)


def test_accepts_prebuilt_keyset_without_rewrapping():
    ks = HMACKeySet([KEY])
    assert Signer(ks).keys is ks


def test_signing_key_defaults_to_most_recently_added():
    signer = Signer([(KEY_A, "old"), (KEY_B, "new")])
    assert signer.signing_key_id == "new"


def test_explicit_signing_key_id_is_respected():
    signer = Signer([(KEY_A, "old"), (KEY_B, "new")], signing_key_id="old")
    assert signer.signing_key_id == "old"


# ---------------------------------------------------------------------------
# sign / verify round trip
# ---------------------------------------------------------------------------


def test_sign_appends_sig_and_exp():
    signer = Signer([KEY])
    signed = signer.sign("https://example.com/a?b=1")
    query = parse_qs(urlparse(signed).query)
    assert "sig" in query and "exp" in query
    assert query["b"] == ["1"]  # original params preserved


def test_sign_then_verify_succeeds():
    signer = Signer([KEY])
    assert signer.verify(signer.sign("https://example.com/a?b=1")) is True


def test_round_trips_query_that_does_not_re_encode_identically():
    # Spaces and repeated keys don't survive a raw round trip; sign() and
    # verify() must canonicalise the query the same way.
    signer = Signer([KEY])
    signed = signer.sign("https://example.com/p?q=hello world&a=1&a=2")
    assert signer.verify(signed) is True


def test_sign_uses_configured_ttl():
    signer = Signer([KEY], ttl=100)
    signed = signer.sign("https://example.com/")
    exp = int(parse_qs(urlparse(signed).query)["exp"][0])
    assert abs(exp - (int(time()) + 100)) <= 2


@pytest.mark.parametrize(
    "tamper",
    [
        lambda u: u.replace("b=1", "b=2"),       # changed query value
        lambda u: u.replace("/a?", "/evil?"),    # changed path
        lambda u: u.replace("https://", "http://"),  # changed scheme
    ],
)
def test_verify_rejects_tampered_url(tamper):
    signer = Signer([KEY])
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(tamper(signed)) is False


def test_verify_rejects_signature_from_unknown_key():
    signed = Signer([KEY_A]).sign("https://example.com/")
    assert Signer([KEY_B]).verify(signed) is False


def test_verify_accepts_rotated_out_key():
    """A signature made with an old key still verifies after rotation."""
    old = Signer([(KEY_A, "old")])
    signed = old.sign("https://example.com/")
    rotated = Signer([(KEY_A, "old"), (KEY_B, "new")])
    assert rotated.verify(signed) is True
    assert rotated.signing_key_id == "new"  # but new signatures use the new key


@pytest.mark.parametrize(
    "query",
    [
        "sig=deadbeef",          # missing exp
        "exp=9999999999",        # missing sig
        "sig=deadbeef&exp=notanint",  # non-integer exp
        "",                      # neither
    ],
)
def test_verify_rejects_missing_or_malformed_params(query):
    signer = Signer([KEY])
    assert signer.verify(f"https://example.com/?{query}") is False


def test_verify_rejects_expired_signature():
    signer = Signer([KEY], ttl=-100)  # already expired on creation
    assert signer.verify(signer.sign("https://example.com/")) is False


def test_skew_allows_recently_expired_signature():
    signer = Signer([KEY], ttl=-100)
    signed = signer.sign("https://example.com/")
    assert signer.verify(signed, skew=0) is False
    assert signer.verify(signed, skew=200) is True


# ---------------------------------------------------------------------------
# ignore_query_params
# ---------------------------------------------------------------------------


def test_signed_url_still_contains_ignored_param():
    # Ignored params are excluded from the signature, not stripped from the URL.
    signer = Signer([KEY], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1&utm=x")
    assert parse_qs(urlparse(signed).query)["utm"] == ["x"]


def test_changing_ignored_param_value_still_verifies():
    signer = Signer([KEY], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1&utm=before")
    assert signer.verify(signed.replace("utm=before", "utm=after")) is True


def test_adding_ignored_param_still_verifies():
    signer = Signer([KEY], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1")
    assert signer.verify(signed + "&utm=added") is True


def test_removing_ignored_param_still_verifies():
    signer = Signer([KEY], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?utm=x&a=1")
    assert signer.verify(signed.replace("utm=x&", "")) is True


def test_non_ignored_param_is_still_protected():
    signer = Signer([KEY], ignore_query_params=["utm"])
    signed = signer.sign("https://example.com/p?a=1&utm=x")
    assert signer.verify(signed.replace("a=1", "a=2")) is False


def test_multiple_ignored_params():
    signer = Signer([KEY], ignore_query_params=["utm_source", "utm_medium"])
    signed = signer.sign("https://example.com/p?a=1&utm_source=s&utm_medium=m")
    tampered = signed.replace("utm_source=s", "utm_source=x").replace(
        "utm_medium=m", "utm_medium=y"
    )
    assert signer.verify(tampered) is True


def test_ignore_list_accepts_any_iterable():
    # A set is a valid Iterable[str]; order-independence is fine since the
    # list is only used for membership tests.
    signer = Signer([KEY], ignore_query_params={"utm"})
    signed = signer.sign("https://example.com/p?a=1&utm=x")
    assert signer.verify(signed.replace("utm=x", "utm=y")) is True


def test_default_signs_every_param():
    # Without an ignore list, any query param is protected.
    signer = Signer([KEY])
    signed = signer.sign("https://example.com/p?utm=x")
    assert signer.verify(signed.replace("utm=x", "utm=y")) is False


def test_one_shot_iterable_ignore_list_is_not_exhausted():
    # A generator must survive being used across both sign() and verify(),
    # and across repeated calls.
    signer = Signer([KEY], ignore_query_params=(p for p in ["utm"]))
    signed = signer.sign("https://example.com/p?a=1&utm=x")  # sign uses it
    assert signer.verify(signed.replace("utm=x", "utm=y")) is True  # verify too
    assert signer.verify(signed.replace("utm=x", "utm=z")) is True  # still works
