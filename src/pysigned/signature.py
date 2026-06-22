import hashlib
import hmac
from collections.abc import Iterable
from time import time
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    ParseResult,
)


DIGEST = "sha512"
# HMAC keys must be at least the digest's output size (NIST SP 800-107).
MIN_KEY_BYTES = hashlib.new(DIGEST).digest_size


class HMACKey:
    def __init__(self, key: bytes, id: str = ""):
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(
                f"key is {len(key)} bytes; "
                f"{DIGEST} requires keys of at least {MIN_KEY_BYTES} bytes"
            )
        self.key = key
        self.id = id or hashlib.sha256(key).hexdigest()

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, HMACKey):
            other = other.key
        return self.key == other

    def __bytes__(self):
        return self.key

    def __repr__(self):
        return f"<HMACKey id={self.id}, bytes={self.key.hex()[:5]}...>"


HMACKeySetValue = tuple[bytes, str] | bytes | HMACKey
HMACKeySetValues = Iterable[HMACKeySetValue]


class HMACKeySet:
    def __init__(self, keys: HMACKeySetValues):
        self._keys: dict[str, HMACKey] = {k.id: k for k in map(self._parse_value, keys)}

    def __getitem__(self, key: str):
        return self._keys[key]

    def __iter__(self):
        return iter(self._keys.values())

    def __reversed__(self):
        return reversed(self._keys.values())

    def __len__(self):
        return len(self._keys)

    @staticmethod
    def _parse_value(value: HMACKeySetValue) -> HMACKey:
        match value:
            case bytes():
                return HMACKey(value)
            case HMACKey():
                return value
            case (_bytes, _id):
                if not isinstance(_bytes, bytes):
                    raise ValueError("Keys in tuples must be bytes")
                if not isinstance(_id, str):
                    raise ValueError("Key ids must be strings.")
                return HMACKey(_bytes, _id)
            case _:
                raise ValueError(f"Invalid key value: {value}")


class Signer:
    """Sign and verify URLs with an HMAC-SHA512 over the URL and an expiry.

    A signer is configured with a set of ``keys``. Several keys may be supplied
    so that keys can be rotated without invalidating signatures that are still
    in flight: signing uses one key, but :meth:`verify` accepts any of them.

    Args:
        keys: The keys to sign and verify with.
        signing_key_id: Id of the key to sign with. Defaults to the most
            recently added key.
        ttl: Seconds a signature stays valid (default 10 minutes).
    """

    def __init__(
        self,
        keys: HMACKeySet | HMACKeySetValues,
        *,
        signing_key_id: str = "",
        ignore_query_params: Iterable[str] | None = None,
        ttl: int = 60 * 10,
    ) -> None:
        self.keys = keys if isinstance(keys, HMACKeySet) else HMACKeySet(keys)
        self.signing_key_id = signing_key_id or next(reversed(self.keys)).id
        # Params excluded from the signed message: our own sig/exp plus any the
        # caller wants ignored. Materialised once so a one-shot iterable works.
        self._excluded = frozenset(("sig", "exp", *(ignore_query_params or ())))
        self.ttl = ttl

    def sign(self, url: str) -> str:
        """Create an HMAC signature over a URL and an expiry timestamp.

        Args:
            url: The URL being signed as a string.

        Returns:
            The signature as a hex string.
        """
        parsed = urlparse(url)
        exp = int(time()) + self.ttl
        signing_key = self.keys[self.signing_key_id]
        signature = hmac.new(
            bytes(signing_key), self._message(parsed, exp), DIGEST
        ).hexdigest()
        query = parse_qsl(parsed.query) + [("sig", signature), ("exp", str(exp))]
        return parsed._replace(query=urlencode(query)).geturl()

    def verify(self, url: str, *, skew: int = 0) -> bool:
        """Verify a signature produced by :meth:`sign`.

        Every configured key is checked, so signatures made with a rotated-out
        key still verify. Comparison is done in constant time to avoid timing
        attacks.
        """
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        sig = params.get("sig")
        try:
            exp = int(params.get("exp", ""))
        except ValueError:
            return False

        if not sig or not exp:
            return False
        if exp + skew <= int(time()):
            return False

        message = self._message(parsed, exp)
        for key in self.keys:
            expected = hmac.new(bytes(key), message, DIGEST).hexdigest()
            if hmac.compare_digest(expected, sig):
                return True
        return False

    def _message(self, parsed: ParseResult, exp: int) -> bytes:
        """Build a stable, unambiguous byte string from the inputs.

        The query is normalised (sig/exp dropped, then re-encoded) so that
        sign() and verify() agree regardless of the incoming encoding.
        Components are joined with a newline (a byte that cannot appear in a URL
        component) so that different field boundaries can never collide.
        """
        pairs = [
            (k, v) for k, v in parse_qsl(parsed.query) if k not in self._excluded
        ]
        canonical = parsed._replace(query=urlencode(pairs))
        parts = (
            str(exp),
            canonical.scheme,
            canonical.netloc,
            canonical.path,
            canonical.params,
            canonical.query,
        )
        return "\n".join(parts).encode("utf-8")
