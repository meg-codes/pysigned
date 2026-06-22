"""Tests for the optional FastAPI extension.

FastAPI is an optional dependency: importing the core ``pysigned`` package
must never require it, since ``pysigned.extensions.fastapi`` is an opt-in
submodule that only gets imported by code that explicitly wants it (and
therefore is expected to have FastAPI installed). The functional tests then
exercise ``SignedRoute`` as a real FastAPI dependency, wired into an app and
driven through ``TestClient``.
"""

import builtins

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from pysigned import HMACKey, KeySet, URLAuth
from pysigned.extensions.fastapi import SignedRoute
from pysigned.keys import MIN_KEY_BYTES


def kb(seed: bytes) -> bytes:
    return (seed * MIN_KEY_BYTES)[:MIN_KEY_BYTES]


def keyset() -> KeySet:
    return KeySet([HMACKey(kb(b"k"))])


def make_app(**route_kwargs) -> FastAPI:
    app = FastAPI()

    @app.get("/a", dependencies=[Depends(SignedRoute(**route_kwargs))])
    def protected():
        return {"ok": True}

    return app


def test_core_import_does_not_require_fastapi(monkeypatch):
    """Importing the core package must succeed without FastAPI installed."""
    import sys

    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name == "fastapi" or name.startswith("fastapi."):
            raise ImportError("simulated: fastapi is not installed")
        return real_import(name, *args, **kwargs)

    for mod in list(sys.modules):
        if mod == "pysigned" or mod.startswith("pysigned."):
            monkeypatch.delitem(sys.modules, mod, raising=False)

    monkeypatch.setattr(builtins, "__import__", blocking_import)

    import importlib

    module = importlib.import_module("pysigned")
    assert hasattr(module, "URLAuth")


def test_signed_route_accepts_valid_signature():
    keys = keyset()
    client = TestClient(make_app(keyset=keys))

    signed_url = URLAuth(keys).sign(str(client.base_url) + "/a?b=1")

    response = client.get(signed_url)
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_signed_route_rejects_missing_signature():
    client = TestClient(make_app(keyset=keyset()))

    response = client.get("/a?b=1")
    assert response.status_code == 403


def test_signed_route_rejects_tampered_url():
    keys = keyset()
    client = TestClient(make_app(keyset=keys))

    signed_url = URLAuth(keys).sign(str(client.base_url) + "/a?b=1")
    tampered = signed_url.replace("b=1", "b=2")

    response = client.get(tampered)
    assert response.status_code == 403


def test_signed_route_honours_ignore_query_params():
    keys = keyset()
    client = TestClient(make_app(keyset=keys, ignore_query_params=["tracking"]))

    signer = URLAuth(keys, ignore_query_params=["tracking"])
    signed_url = signer.sign(str(client.base_url) + "/a?b=1")
    # Appending an ignored param after signing must not break verification.
    url_with_extra = signed_url + "&tracking=xyz"

    response = client.get(url_with_extra)
    assert response.status_code == 200


@pytest.mark.parametrize(
    "mutate",
    [
        lambda url: url.replace("sig=", "sig=tampered"),
        lambda url: url.split("&exp=")[0],
    ],
    ids=["bad-signature", "missing-expiry"],
)
def test_signed_route_rejects_malformed_signatures(mutate):
    keys = keyset()
    client = TestClient(make_app(keyset=keys))

    signed_url = URLAuth(keys).sign(str(client.base_url) + "/a?b=1")
    response = client.get(mutate(signed_url))
    assert response.status_code == 403


def test_signed_route_custom_error_status():
    client = TestClient(make_app(keyset=keyset(), error_status=401))

    response = client.get("/a?b=1")
    assert response.status_code == 401


def test_signed_route_custom_ttl_expires_immediately():
    keys = keyset()
    client = TestClient(make_app(keyset=keys, ttl=-1))

    signed_url = URLAuth(keys, ttl=-1).sign(str(client.base_url) + "/a?b=1")

    response = client.get(signed_url)
    assert response.status_code == 403


def test_signed_route_with_keyset_getter():
    keys = keyset()

    async def keyset_getter(request):
        return keys

    client = TestClient(make_app(keyset_getter=keyset_getter))

    signed_url = URLAuth(keys).sign(str(client.base_url) + "/a?b=1")
    response = client.get(signed_url)
    assert response.status_code == 200


def test_signed_route_keyset_getter_receives_request():
    keys = keyset()
    seen_paths = []

    async def keyset_getter(request):
        seen_paths.append(request.url.path)
        return keys

    client = TestClient(make_app(keyset_getter=keyset_getter))
    signed_url = URLAuth(keys).sign(str(client.base_url) + "/a?b=1")

    client.get(signed_url)
    assert seen_paths == ["/a"]


def test_signed_route_accepts_url_auth_instance():
    keys = keyset()
    auth = URLAuth(keys)
    client = TestClient(make_app(url_auth=auth))

    signed_url = auth.sign(str(client.base_url) + "/a?b=1")

    response = client.get(signed_url)
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_signed_route_url_auth_rejects_missing_signature():
    client = TestClient(make_app(url_auth=URLAuth(keyset())))

    response = client.get("/a?b=1")
    assert response.status_code == 403


def test_signed_route_url_auth_honours_custom_error_status():
    client = TestClient(make_app(url_auth=URLAuth(keyset()), error_status=401))

    response = client.get("/a?b=1")
    assert response.status_code == 401


def test_signed_route_url_auth_uses_instance_config():
    """An ignore_query_params baked into the url_auth instance is respected."""
    keys = keyset()
    auth = URLAuth(keys, ignore_query_params=["tracking"])
    client = TestClient(make_app(url_auth=auth))

    signed_url = auth.sign(str(client.base_url) + "/a?b=1")
    response = client.get(signed_url + "&tracking=xyz")
    assert response.status_code == 200


def test_signed_route_require_kid_accepts_matching_kid():
    keys = keyset()
    client = TestClient(make_app(keyset=keys, require_kid=True))

    signed_url = URLAuth(keys, require_kid=True).sign(str(client.base_url) + "/a?b=1")

    response = client.get(signed_url)
    assert response.status_code == 200


def test_signed_route_require_kid_rejects_url_without_kid():
    keys = keyset()
    client = TestClient(make_app(keyset=keys, require_kid=True))

    # Signed without require_kid, so the URL carries no kid.
    signed_url = URLAuth(keys).sign(str(client.base_url) + "/a?b=1")

    response = client.get(signed_url)
    assert response.status_code == 403


def test_signed_route_rejects_no_keyset_args():
    with pytest.raises(ValueError):
        SignedRoute()


def test_signed_route_rejects_both_keyset_args():
    keys = keyset()

    async def keyset_getter(request):
        return keys

    with pytest.raises(ValueError):
        SignedRoute(keyset=keys, keyset_getter=keyset_getter)


def test_signed_route_rejects_url_auth_with_keyset():
    keys = keyset()
    with pytest.raises(ValueError):
        SignedRoute(url_auth=URLAuth(keys), keyset=keys)


@pytest.mark.parametrize(
    "extra",
    [
        {"signing_key_id": "k"},
        {"ignore_query_params": ["tracking"]},
        {"ttl": 30},
        {"require_kid": True},
    ],
    ids=["signing_key_id", "ignore_query_params", "ttl", "require_kid"],
)
def test_signed_route_rejects_url_auth_with_forwarded_args(extra):
    with pytest.raises(ValueError):
        SignedRoute(url_auth=URLAuth(keyset()), **extra)


def test_signed_route_keyset_getter_returning_none_raises():
    async def keyset_getter(request):
        return None

    route = SignedRoute(keyset_getter=keyset_getter)

    class FakeRequest:
        url = "http://testserver/a?b=1"

    import asyncio

    with pytest.raises(ValueError):
        asyncio.run(route(FakeRequest()))
