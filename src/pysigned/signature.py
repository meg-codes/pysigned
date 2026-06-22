from collections.abc import Iterable
from time import time
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    ParseResult,
)

from .backends import KeySet


class URLAuth:
    """Sign and verify URLs over the URL and an expiry, via a pluggable backend.

    A signer is configured with a set of ``keys``. Several keys may be supplied
    so that keys can be rotated without invalidating signatures that are still
    in flight: signing uses one key, but :meth:`verify` accepts any of them. The
    keys may mix algorithms -- an HMAC key and an Ed25519 key can live in the
    same :class:`~pysigned.backends.KeySet`.

    The cryptography is delegated to the keyset's :class:`~pysigned.backends.Backend`,
    which dispatches on each key's type. Everything else -- query
    canonicalisation, expiry, rotation -- is backend-agnostic.

    Args:
        keys: A :class:`~pysigned.backends.KeySet`, or raw values that are
            wrapped in one. Raw bytes are read as HMAC keys; pass wrapped
            :class:`~pysigned.keys.Ed25519PrivateKey` /
            :class:`~pysigned.keys.Ed25519PublicKey` for Ed25519.
        signing_key_id: Id of the key to sign with. Defaults to the most
            recently added key (which must be able to sign).
        ttl: Seconds a signature stays valid (default 10 minutes).
    """

    def __init__(
        self,
        keys: KeySet | Iterable,
        *,
        signing_key_id: str = "",
        ignore_query_params: Iterable[str] | None = None,
        ttl: int = 60 * 10,
    ) -> None:
        self.keys = keys if isinstance(keys, KeySet) else KeySet(keys)
        self.backend = self.keys.backend
        self.signing_key_id = signing_key_id or next(reversed(self.keys)).id
        # Params excluded from the signed message: our own sig/exp plus any the
        # caller wants ignored. Materialised once so a one-shot iterable works.
        self._excluded = frozenset(("sig", "exp", *(ignore_query_params or ())))
        self.ttl = ttl

    def sign(self, url: str) -> str:
        """Sign a URL, returning it with ``sig`` and ``exp`` query params added.

        Args:
            url: The URL being signed as a string.

        Returns:
            The signed URL as a string.
        """
        parsed = urlparse(url)
        exp = int(time()) + self.ttl
        signing_key = self.keys[self.signing_key_id]
        signature = self.backend.sign(signing_key, self._message(parsed, exp))
        query = parse_qsl(parsed.query) + [("sig", signature), ("exp", str(exp))]
        return parsed._replace(query=urlencode(query)).geturl()

    def verify(self, url: str, *, skew: int = 0) -> bool:
        """Verify a signature produced by :meth:`sign`.

        Every configured key is checked, so signatures made with a rotated-out
        key still verify.
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
            if self.backend.verify(key, message, sig):
                return True
        return False

    def _message(self, parsed: ParseResult, exp: int) -> bytes:
        """Build a stable, unambiguous byte string from the inputs.

        The query is normalised (sig/exp dropped, then re-encoded) so that
        sign() and verify() agree regardless of the incoming encoding.
        Components are joined with a newline (a byte that cannot appear in a URL
        component) so that different field boundaries can never collide.
        """
        pairs = [(k, v) for k, v in parse_qsl(parsed.query) if k not in self._excluded]
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
