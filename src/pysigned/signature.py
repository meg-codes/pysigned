from collections.abc import Iterable
from time import time
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    ParseResult,
)

from .keys import KeySet


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
            :class:`~pysigned.keys.Ed25519KeyPair` /
            :class:`~pysigned.keys.Ed25519PublicKey` for Ed25519.
        signing_key_id: Id of the key to sign with. Defaults to the most
            recently added key (which must be able to sign).
        ignore_query_params: Query params excluded from the signed message, so
            they may be added, removed, or changed without breaking the
            signature (e.g. analytics tags).
        require_kid: When ``True``, :meth:`sign` tags each URL with a ``kid``
            naming the signing key, and :meth:`verify` consults *only* that key
            instead of scanning the whole set -- rejecting any URL with a
            missing or unknown ``kid``. Signer and verifier must agree on this
            flag: a require_kid verifier rejects signatures minted without a
            ``kid``. When ``False`` (the default), any ``kid`` in the URL is
            ignored and every key is tried.
        ttl: Seconds a signature stays valid (default 10 minutes).
    """

    def __init__(
        self,
        keys: KeySet | Iterable,
        *,
        signing_key_id: str = "",
        ignore_query_params: Iterable[str] | None = None,
        require_kid: bool = False,
        ttl: int = 60 * 10,
    ) -> None:
        self.keys = keys if isinstance(keys, KeySet) else KeySet(keys)
        self.backend = self.keys.backend
        self.signing_key_id = signing_key_id or next(reversed(self.keys)).id
        # Params excluded from the signed message: our own sig/exp plus any the
        # caller wants ignored. Materialised once so a one-shot iterable works.
        self._excluded = frozenset(("sig", "exp", "kid", *(ignore_query_params or ())))
        self.ttl = ttl
        self.require_kid = require_kid

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
        added = [("sig", signature), ("exp", str(exp))]
        if self.require_kid:
            added.append(("kid", signing_key.id))
        query = parse_qsl(parsed.query) + added
        return parsed._replace(query=urlencode(query)).geturl()

    def verify(self, url: str, *, skew: int = 0) -> bool:
        """Verify a signature produced by :meth:`sign`.

        Every configured key is checked, so signatures made with a rotated-out
        key still verify -- unless ``require_kid`` is set, in which case only the
        key named by the URL's ``kid`` is consulted (see :class:`URLAuth`).
        """
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))

        sig = params.get("sig")
        kid = params.get("kid")
        try:
            exp = int(params.get("exp", ""))
        except ValueError:
            return False

        if not sig or not exp:
            return False
        if exp + skew <= int(time()):
            return False

        message = self._message(parsed, exp)

        if self.require_kid:
            if not kid:
                return False
            try:
                key = self.keys[kid]
            except KeyError:
                return False
            return self.backend.verify(key, message, sig)

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
        pairs = sorted(
            (k, v) for k, v in parse_qsl(parsed.query) if k not in self._excluded
        )
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
