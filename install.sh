#!/bin/sh
# Owner-console entry point; strict mode is the only supported mode.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$BASE/vpndns.py" install --strict "$@"
