"""FastAPI integration: a dependency that verifies signed URLs.

Requires the ``fastapi`` extra (``pip install pysigned[fastapi]``). This
module is only imported by code that explicitly opts into it, so the core
``pysigned`` package stays installable without FastAPI.
"""

import collections.abc

from typing import Iterable, Protocol

from fastapi import Request, status
from fastapi.exceptions import HTTPException

from pysigned.keys import KeySet
from pysigned import URLAuth


class KeysetGetter(Protocol):
    """Callable that resolves a :class:`~pysigned.KeySet` for a request.

    Use this instead of a static ``keyset`` when the keys depend on
    per-request state, e.g. fetching keys for a tenant from a database.
    """

    async def __call__(self, request: Request) -> KeySet | Iterable:
        pass  # pragma: no cover


class SignedRoute:
    """A FastAPI dependency that verifies a request's URL signature.

    Wraps :class:`~pysigned.URLAuth` for use with FastAPI's dependency
    injection. Wire it in via ``Depends``, either on a single route or
    globally on a router/app, and it raises an :class:`~fastapi.HTTPException`
    when the request's URL fails verification.

    There are two ways to configure it. Either pass a fully-built
    ``url_auth`` instance and the dependency verifies against it directly, or
    pass ``keyset``/``keyset_getter`` (plus optional tuning) and the dependency
    builds a :class:`~pysigned.URLAuth` per request. The two styles are mutually
    exclusive: ``url_auth`` already carries its own ``signing_key_id``,
    ``ignore_query_params``, ``ttl``, and ``require_kid``, so those must not be
    passed alongside it.

    Args:
        url_auth: A pre-built :class:`~pysigned.URLAuth` to verify against.
            Mutually exclusive with ``keyset`` and ``keyset_getter``; when
            given, the per-request tuning args (``signing_key_id``,
            ``ignore_query_params``, ``ttl``, ``require_kid``) must be left
            unset because they are configured on the instance itself.
        keyset: A fixed :class:`~pysigned.KeySet` to verify against. Mutually
            exclusive with ``url_auth`` and ``keyset_getter``.
        keyset_getter: An async callable that resolves a
            :class:`~pysigned.KeySet` for cases
            where the keys aren't known until request time. Mutually
            exclusive with ``url_auth`` and ``keyset``.
        signing_key_id: Id of the key new signatures would be signed with.
            Unused for verification, but forwarded to
            :class:`~pysigned.URLAuth`.
        ignore_query_params: Query params excluded from the signed message,
            e.g. tracking params appended after signing.
        error_status: HTTP status code raised when verification fails.
            Defaults to 403 Forbidden.
        ttl: Overrides :class:`~pysigned.URLAuth`'s default signature
            lifetime, in seconds.
        require_kid: When ``True``, only the key named by each URL's ``kid`` is
            consulted and URLs without a known ``kid`` are rejected. Forwarded
            to :class:`~pysigned.URLAuth`; see its docs for the full semantics.
    """

    def __init__(
        self,
        *,
        url_auth: URLAuth | None = None,
        keyset: KeySet | collections.abc.Iterable | None = None,
        keyset_getter: KeysetGetter | None = None,
        signing_key_id: str = "",
        ignore_query_params: Iterable[str] | None = None,
        error_status: int = status.HTTP_403_FORBIDDEN,
        ttl: int | None = None,
        require_kid: bool = False,
    ):
        base_configs = [c for c in (keyset, keyset_getter, url_auth) if c is not None]
        if len(base_configs) == 0:
            raise ValueError("Must set one of url_auth, keyset, or keyset_getter.")
        if len(base_configs) > 1:
            raise ValueError(
                "url_auth, keyset, and keyset_getter are mutually exclusive."
            )
        if url_auth is not None and any(
            [signing_key_id, ignore_query_params, ttl is not None, require_kid]
        ):
            raise ValueError(
                "signing_key_id, ignore_query_params, ttl, and require_kid are "
                "configured on the URLAuth instance; don't also pass them to "
                "SignedRoute when url_auth is provided."
            )
        self.url_auth = url_auth
        self.keyset = keyset
        self.keyset_getter = keyset_getter
        self.error_status = error_status
        self.signing_key_id = signing_key_id
        self.ignore_query_params = ignore_query_params
        self.ttl = ttl
        self.require_kid = require_kid

    async def __call__(self, request: Request):
        """Verify the request's URL, raising on failure.

        Args:
            request: The incoming request, supplied by FastAPI.

        Raises:
            HTTPException: With ``error_status`` if the URL's signature is
                missing, invalid, or expired.
            ValueError: If ``keyset_getter`` resolves to an empty keyset.
        """
        url = str(request.url)
        if self.url_auth is not None:
            if not self.url_auth.verify(url):
                raise HTTPException(status_code=self.error_status)
            return

        keys = self.keyset
        if not keys and self.keyset_getter:
            keys = await self.keyset_getter(request)
        if not keys:
            raise ValueError("Could not set keys for verifier.")
        kwargs = {}
        if self.ttl is not None:
            kwargs["ttl"] = self.ttl
        verifier = URLAuth(
            keys=keys,
            signing_key_id=self.signing_key_id,
            ignore_query_params=self.ignore_query_params,
            require_kid=self.require_kid,
            **kwargs,
        )
        if not verifier.verify(url):
            raise HTTPException(status_code=self.error_status)
