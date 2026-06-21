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

    Args:
        keyset: A fixed :class:`~pysigned.KeySet` to verify against. Mutually
            exclusive with ``keyset_getter``.
        keyset_getter: An async callable that resolves a
            :class:`~pysigned.KeySet` for cases
            where the keys aren't known until request time. Mutually
            exclusive with ``keyset``.
        signing_key_id: Id of the key new signatures would be signed with.
            Unused for verification, but forwarded to
            :class:`~pysigned.URLAuth`.
        ignore_query_params: Query params excluded from the signed message,
            e.g. tracking params appended after signing.
        error_status: HTTP status code raised when verification fails.
            Defaults to 403 Forbidden.
        ttl: Overrides :class:`~pysigned.URLAuth`'s default signature
            lifetime, in seconds.
    """

    def __init__(
        self,
        *,
        keyset: KeySet | collections.abc.Iterable | None = None,
        keyset_getter: KeysetGetter | None = None,
        signing_key_id: str = "",
        ignore_query_params: Iterable[str] | None = None,
        error_status: int = status.HTTP_403_FORBIDDEN,
        ttl: int | None = None,
    ):
        if keyset is None and keyset_getter is None:
            raise ValueError("Must set one of keyset or keyset_getter.")
        if keyset and keyset_getter:
            raise ValueError("keyset and keyset_getter are mutually exclusive.")
        self.keyset = keyset
        self.keyset_getter = keyset_getter
        self.error_status = error_status
        self.signing_key_id = signing_key_id
        self.ignore_query_params = ignore_query_params
        self.ttl = ttl

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
            **kwargs,
        )
        if not verifier.verify(url):
            raise HTTPException(status_code=self.error_status)
