"""Tests for the key types and KeySet in pysigned.keys."""

import hashlib
from dataclasses import dataclass

import pytest

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
    assert HMACKey(KEY).id == hashlib.sha512(KEY).hexdigest()


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
    key = HMACKey(buf)
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
    assert Ed25519PublicKey(raw).id == hashlib.sha512(raw).hexdigest()


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
    assert PAIR.id == hashlib.sha512(raw).hexdigest()


def test_keypair_explicit_id_is_kept():
    assert Ed25519KeyPair.from_private_bytes(b"s" * 32, id="kid-1").id == "kid-1"


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
    assert ks[hashlib.sha512(KEY).hexdigest()].key == KEY


def test_raw_bytes_are_read_as_hmac_not_ed25519():
    # Raw bytes are unambiguously an HMAC key; Ed25519 keys must be wrapped.
    (key,) = KeySet([b"k" * 64])
    assert isinstance(key, HMACKey)


def test_accepts_bytes_id_tuple():
    ks = KeySet([(KEY, "kid-1")])
    assert ks["kid-1"].key == KEY


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


def test_duplicate_ids_collapse_to_last():
    ks = KeySet([(kb(b"a"), "dup"), (kb(b"b"), "dup")])
    assert len(ks) == 1
    assert ks["dup"].key == kb(b"b")


def test_keyset_contents_are_read_only():
    ks = KeySet([KEY])
    with pytest.raises(TypeError):
        ks._keys["x"] = HMACKey(KEY_A)


def test_mixes_algorithms():
    ks = KeySet([HMACKey(KEY, id="hmac"), PAIR_A])
    assert len(ks) == 2
    assert isinstance(ks["hmac"], HMACKey)
    assert ks[PAIR_A.id] is PAIR_A


def test_keypair_and_matching_public_collapse_by_id():
    # Same identity -> same id -> last one wins.
    ks = KeySet([PAIR, PAIR.public()])
    assert len(ks) == 1
