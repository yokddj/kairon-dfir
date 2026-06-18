#!/usr/bin/env bash
set -euo pipefail

patterns=(
  'volatility3*.whl'
  'volatility3*.tar.gz'
  'vol.py'
  '*.raw'
  '*.mem'
  '*.vmem'
  '*.dmp'
  '*.lime'
  '*.aff4'
  '*symbols*.zip'
)

fail=0

for pattern in "${patterns[@]}"; do
  while IFS= read -r path; do
    case "$path" in
      ./.git/*|backend/.pytest_cache/*|frontend/node_modules/*) continue ;;
      backend/tests/fixtures/memory/*.json) continue ;;
    esac
    [[ "$(basename "$path")" == $pattern ]] || continue
    echo "Forbidden memory/Volatility artifact candidate: $path" >&2
    fail=1
  done < <(if [[ "${1:-}" == "--all" ]]; then find . -type f -print; else git ls-files; fi)
done

while IFS= read -r path; do
  case "$path" in
    .git/*|frontend/node_modules/*) continue ;;
  esac
  if [[ "$(basename "$path")" == "volatility3" ]]; then
    echo "Forbidden vendored volatility3 source directory candidate found: $path" >&2
    fail=1
  fi
done < <(if [[ "${1:-}" == "--all" ]]; then find . -type d -print; else git ls-files | xargs -n1 dirname | sort -u; fi)

exit "$fail"
