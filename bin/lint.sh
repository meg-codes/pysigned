#!/bin/sh
# Run linters
if [ "$1" = "--fix" ]; then
echo "Running ruff format..."
uv run ruff format 
echo "Running ty fix..."
uv run ty --fix
else
echo "Running ruff check..."
uv run ruff check
echo "Running ty check..."
uv run ty check
fi