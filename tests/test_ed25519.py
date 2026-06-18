import hashlib
from time import time
from urllib.parse import parse_qs, urlparse

import pytest

from pysigned import (
    Backend,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    HMACKey,
    KeySet,
    URLAuth,
)


def gen() -> Ed25519PrivateKey:
    """A fresh random private key."""
    return Ed25519PrivateKey.generate()


# A couple of stable keys for tests that need determinism / two identities.
SK = Ed25519PrivateKey.from_private_bytes(b"s" * 32)
SK_A = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
SK_B = Ed25519PrivateKey.from_private_bytes(b"b" * 32)


# ---------------------------------------------------------------------------
# Ed25519PrivateKey / Ed25519PublicKey construction & validation
# ---------------------------------------------------------------------------


def test_generate_produces_distinct_keys():
    assert gen().key != gen().key


def test_from_private_bytes_round_trips_seed():
    assert bytes(Ed25519PrivateKey.from_private_bytes(b"s" * 32)) == b"s" * 32


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_private_seed_must_be_32_bytes(length):
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519PrivateKey(b"x" * length)


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_public_key_must_be_32_bytes(length):
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519PublicKey(b"x" * length)


def test_public_key_helper_round_trips():
    pub = SK.public_key()
    assert isinstance(pub, Ed25519PublicKey)
    assert bytes(pub) == SK.public_bytes()


# ---------------------------------------------------------------------------
# id derivation: from the public key, never the seed
# ---------------------------------------------------------------------------


def test_id_defaults_to_sha512_of_public_key():
    assert SK.id == hashlib.sha512(SK.public_bytes()).hexdigest()


def test_private_and_its_public_key_share_an_id():
    pub = Ed25519PublicKey.from_public_bytes(SK.public_bytes())
    assert SK.id == pub.id


def test_explicit_id_is_kept():
    assert Ed25519PrivateKey(b"s" * 32, id="kid-1").id == "kid-1"


def test_repr_does_not_leak_the_seed():
    rep = repr(Ed25519PrivateKey(b"s" * 32, id="kid-1"))
    assert "kid-1" in rep
    assert (b"s" * 32).hex()[:5] not in rep  # seed must not appear
    assert SK.public_bytes().hex()[:5] in rep  # public fingerprint instead


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attr", ["key", "id"])
def test_key_is_frozen(attr):
    key = Ed25519PrivateKey(b"s" * 32)
    with pytest.raises(AttributeError):
        setattr(key, attr, b"z" * 32)


def test_key_copies_seed_so_source_mutation_is_isolated():
    buf = bytearray(b"s" * 32)
    key = Ed25519PrivateKey(buf)
    buf[0] ^= 0xFF
    assert key.key == b"s" * 32


# ---------------------------------------------------------------------------
# KeySet construction / parse_key
# ---------------------------------------------------------------------------


def test_accepts_private_and_public_keys():
    pub = SK_B.public_key()
    ks = KeySet([SK_A, pub])
    assert ks[SK_A.id] is SK_A
    assert ks[pub.id] is pub


def test_raw_bytes_are_read_as_hmac_not_ed25519():
    # Raw bytes are unambiguously an HMAC key now; Ed25519 keys must be wrapped.
    (key,) = KeySet([b"k" * 64])
    assert isinstance(key, HMACKey)


def test_len_counts_keys():
    assert len(KeySet([SK_A, SK_B])) == 2


def test_getitem_missing_raises_keyerror():
    with pytest.raises(KeyError):
        KeySet([SK])["nope"]


def test_keyset_contents_are_read_only():
    ks = KeySet([SK])
    with pytest.raises(TypeError):
        ks._keys["x"] = SK_A


def test_private_and_matching_public_collapse_by_id():
    # Same identity -> same id -> last one wins.
    ks = KeySet([SK, SK.public_key()])
    assert len(ks) == 1


# ---------------------------------------------------------------------------
# URLAuth construction
# ---------------------------------------------------------------------------


def test_signer_uses_backend_from_keyset():
    signer = URLAuth(KeySet([SK]))
    assert isinstance(signer.backend, Backend)


def test_signing_key_defaults_to_most_recently_added():
    a = Ed25519PrivateKey(b"a" * 32, id="old")
    b = Ed25519PrivateKey(b"b" * 32, id="new")
    assert URLAuth(KeySet([a, b])).signing_key_id == "new"


# ---------------------------------------------------------------------------
# sign / verify round trip -- the headline asymmetric guarantee
# ---------------------------------------------------------------------------


def test_sign_appends_sig_and_exp():
    signer = URLAuth(KeySet([SK]))
    signed = signer.sign("https://example.com/a?b=1")
    query = parse_qs(urlparse(signed).query)
    assert "sig" in query and "exp" in query
    assert query["b"] == ["1"]


def test_sign_with_private_verify_with_public_only():
    sk = gen()
    signed = URLAuth(KeySet([sk])).sign("https://example.com/a?b=1")

    # Verifier side holds only the public key -- no secret.
    pub = Ed25519PublicKey.from_public_bytes(sk.public_bytes())
    assert URLAuth(KeySet([pub])).verify(signed) is True


def test_round_trips_query_that_does_not_re_encode_identically():
    signer = URLAuth(KeySet([SK]))
    signed = signer.sign("https://example.com/p?q=hello world&a=1&a=2")
    assert signer.verify(signed) is True


@pytest.mark.parametrize(
    "tamper",
    [
        lambda u: u.replace("b=1", "b=2"),
        lambda u: u.replace("/a?", "/evil?"),
        lambda u: u.replace("https://", "http://"),
    ],
)
def test_verify_rejects_tampered_url(tamper):
    signer = URLAuth(KeySet([SK]))
    signed = signer.sign("https://example.com/a?b=1")
    assert signer.verify(tamper(signed)) is False


def test_verify_rejects_signature_from_unknown_key():
    signed = URLAuth(KeySet([SK_A])).sign("https://example.com/")
    assert URLAuth(KeySet([SK_B.public_key()])).verify(signed) is False


def test_verify_accepts_rotated_out_key():
    old = URLAuth(KeySet([Ed25519PrivateKey(b"a" * 32, id="old")]))
    signed = old.sign("https://example.com/")
    rotated = URLAuth(
        KeySet(
            [
                Ed25519PrivateKey(b"a" * 32, id="old"),
                Ed25519PrivateKey(b"b" * 32, id="new"),
            ]
        )
    )
    assert rotated.verify(signed) is True
    assert rotated.signing_key_id == "new"


@pytest.mark.parametrize(
    "query",
    [
        "sig=deadbeef",
        "exp=9999999999",
        "sig=deadbeef&exp=notanint",
        "sig=nothex&exp=9999999999",
        "",
    ],
)
def test_verify_rejects_missing_or_malformed_params(query):
    signer = URLAuth(KeySet([SK]))
    assert signer.verify(f"https://example.com/?{query}") is False


def test_verify_rejects_expired_signature():
    signer = URLAuth(KeySet([SK]), ttl=-100)
    assert signer.verify(signer.sign("https://example.com/")) is False


def test_skew_allows_recently_expired_signature():
    signer = URLAuth(KeySet([SK]), ttl=-100)
    signed = signer.sign("https://example.com/")
    assert signer.verify(signed, skew=0) is False
    assert signer.verify(signed, skew=200) is True


def test_sign_uses_configured_ttl():
    signer = URLAuth(KeySet([SK]), ttl=100)
    signed = signer.sign("https://example.com/")
    exp = int(parse_qs(urlparse(signed).query)["exp"][0])
    assert abs(exp - (int(time()) + 100)) <= 2


# ---------------------------------------------------------------------------
# Signing requires a private key
# ---------------------------------------------------------------------------


def test_signing_with_public_only_keyset_raises():
    signer = URLAuth(KeySet([SK.public_key()]))
    with pytest.raises(TypeError, match="public keys cannot sign"):
        signer.sign("https://example.com/")
