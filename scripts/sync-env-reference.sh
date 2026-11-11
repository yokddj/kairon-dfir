#!/usr/bin/env bash
# Usage: scripts/sync-env-reference.sh [path/to/.env]
#
# Appends to .env, commented, every setting of config/defaults.env it does not mention yet (set or
# commented), with the default and its explanation, so operators find every option in .env. Never
# changes a line already there; an upgrade adds the settings a release introduces.
#
# Run by setup.sh when it writes .env and on every upgrade (through migrate_memory_allowlists);
# safe to run by hand at any time.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

main() {
  local env_file="$1" defaults_file="$2"
  [[ -f "$env_file" && -f "$defaults_file" ]] || return 0
  local present block
  present="$(grep -oE '^[#[:space:]]*[A-Z][A-Z0-9_]*=' "$env_file" | sed -E 's/^[#[:space:]]*//; s/=$//' | tr '\n' ' ')"
  block="$(awk -v present=" ${present} " '
    /^# ----/ { section = $0; notes = ""; next }
    /^# ====/ || /^# Further settings/ || /^# Kairon DFIR internal defaults/ || /^# Documentation status/ { next }
    /^#/ { notes = notes $0 "\n"; next }
    /^[[:space:]]*$/ { notes = ""; next }
    /^[A-Z][A-Z0-9_]*=/ {
      key = $0; sub(/=.*/, "", key)
      if (index(present, " " key " ") == 0) {
        if (section != shown) { printf "\n%s\n", section; shown = section }
        printf "%s# %s\n", notes, $0
      }
      notes = ""
    }' "$defaults_file")"
  [[ -n "$block" ]] || return 0
  {
    echo ""
    echo "# ===================== Settings reference (added $(date -u +%Y-%m-%d)) ====================="
    echo "# Every other setting, commented, with its default (config/defaults.env). Uncomment a line"
    echo "# to change it, then apply with scripts/upgrade.sh (or: docker compose up -d)."
    printf '%s\n' "$block"
  } >> "$env_file"
}

main "${1:-$ROOT_DIR/.env}" "$ROOT_DIR/config/defaults.env"
