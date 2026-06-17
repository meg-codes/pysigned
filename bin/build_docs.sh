#!/bin/sh
# Build the documentation site into ./site
# Pass --serve to run a live-reloading dev server instead.
set -e

if [ "$1" = "--serve" ]; then
    exec uv run mkdocs serve
fi

uv run mkdocs build --strict
