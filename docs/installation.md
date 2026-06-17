# Installation

`pysigned` requires **Python 3.13+**.

The HMAC backend uses only the Python standard library, so the base install has
no third-party dependencies. The Ed25519 backend depends on
[`cryptography`](https://pypi.org/project/cryptography/), which is published as
an optional `ed25519` extra — install it only when you need asymmetric signing.

## uv

```sh
uv add pysigned             # HMAC only (no dependencies)
uv add 'pysigned[ed25519]'  # adds Ed25519 support
```

To install into the current environment without adding it to a project:

```sh
uv pip install pysigned
```

## pip

```sh
pip install pysigned             # HMAC only (no dependencies)
pip install 'pysigned[ed25519]'  # adds Ed25519 support
```

## Verifying the install

```python
import pysigned

print(pysigned.__all__)
```
