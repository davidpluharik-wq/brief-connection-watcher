#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Prefer this checkout's environment, including when launched from an icon.
if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
    exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/brief_connection_watcher.py" "$@"
fi
exec python3 "$SCRIPT_DIR/brief_connection_watcher.py" "$@"
