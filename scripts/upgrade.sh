#!/usr/bin/env bash
# Kairon DFIR upgrade wrapper. Calls setup.sh --upgrade.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/setup.sh" --upgrade "$@"
