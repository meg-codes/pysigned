# Installation

`pysigned` requires **Python 3.11+**.

## uv

```sh
uv add pysigned
```

To install into the current environment without adding it to a project:

```sh
uv pip install pysigned
```

## pip

```sh
pip install pysigned
```

## Verifying the install

```python
import pysigned

print(pysigned.__all__)
```

## FastAPI extension

[`SignedRoute`][pysigned.extensions.fastapi.SignedRoute] is an optional
FastAPI dependency and isn't installed by default. Pull it in with the
`fastapi` extra:

```sh
uv add "pysigned[fastapi]"
```

```sh
pip install "pysigned[fastapi]"
```

See [Usage](usage.md#fastapi-integration) for how to wire it into a route.
