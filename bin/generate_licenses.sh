#!/bin/sh
# Generate third-party licenses file
uv run pip-licenses --format=plain-vertical --with-license-file --no-license-path > THIRD-PARTY-LICENSES