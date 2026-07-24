#!/usr/bin/env bash
# Repository-wide scan for accidentally-committed real infrastructure
# metadata: private deployment IPs, hardcoded root-login SSH targets,
# real "/root/..." deployment paths, and known real personal usernames.
#
# Exits non-zero and prints the offending lines if anything real is found
# outside the explicit, reviewed allowlists below. This replaces an older
# check that only looked for one specific IP in a hardcoded list of doc
# files -- that narrow scope is exactly why the leak this script now
# guards against went unnoticed for weeks.
#
# Allowed everywhere (never flagged):
#   - localhost, 127.0.0.1, 0.0.0.0
#   - RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
#   - backend/tests/** -- this project's DFIR test suite legitimately uses
#     realistic-looking private IPs and "/root/..." paths as simulated
#     victim-machine/evidence data. That is expected test content, not
#     real infrastructure, and excluding it here is a deliberate, reviewed
#     decision -- see the security audit this script was added from.
#
# Known real personal usernames are checked via an explicit, maintained
# list rather than a generic "home directory" regex: this repo's test
# fixtures intentionally contain many fictional /Users/<name> and
# C:\Users\<name> paths (simulated victim usernames), so a generic
# pattern would be too noisy to be useful. If a real personal username is
# ever found in the repository, add it to KNOWN_REAL_USERNAMES below as
# part of removing it, so this script catches any recurrence.
KNOWN_REAL_USERNAMES=()

set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FAILED=0
# Both backend/tests/** and any *.test.ts(x) file (this project's DFIR
# test suites routinely embed realistic-looking private IPs and paths as
# simulated victim-machine data across both backend and frontend tests).
FIXTURE_EXCLUDES=(':!backend/tests/**' ':!**/*.test.ts' ':!**/*.test.tsx')

report() {
  local label="$1"; shift
  local matches
  if matches="$("$@" 2>/dev/null)" && [[ -n "$matches" ]]; then
    echo "ERROR: $label"
    echo "$matches"
    FAILED=1
  fi
}

# 1. RFC1918 private IPs outside test fixtures. The surrounding
#    non-digit/non-dot boundary keeps this from matching a substring of a
#    longer number, or from mistaking prose for an address.
report "private (RFC1918) IP address outside test fixtures" \
  git grep -nEI '(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)' \
  -- . "${FIXTURE_EXCLUDES[@]}"

# 2. Hardcoded root-login SSH target.
report "hardcoded 'root@' SSH login outside test fixtures" \
  git grep -niI 'root@' \
  -- . "${FIXTURE_EXCLUDES[@]}"

# 3. "/root/..." paths outside test fixtures and the explicit, reviewed
#    set of files that use "/root/..." only as a generic, non-host-
#    specific default directory convention (never tied to one real host)
#    or as forensic path-pattern matching against a *victim* machine's
#    filesystem (a real Kairon feature, not a leak of Kairon's own infra).
report "hardcoded /root/... path outside test fixtures and reviewed defaults" \
  git grep -nEI '(^|[^a-zA-Z0-9_/])/root/[a-zA-Z]' \
  -- . "${FIXTURE_EXCLUDES[@]}" \
  ':!deploy.sh' \
  ':!scripts/deploy_remote.sh' \
  ':!scripts/backup.sh' \
  ':!scripts/restore.sh' \
  ':!docs/deployment_remote.md' \
  ':!docker/memory-worker/Dockerfile' \
  ':!docker/symbol-fetcher/Dockerfile' \
  ':!backend/app/core/evidence_platforms.py' \
  ':!backend/app/ingest/linux/discovery.py' \
  ':!backend/app/ingest/linux/helpers.py' \
  ':!backend/app/ingest/linux/shell_history.py' \
  ':!backend/app/ingest/linux/ssh_artifacts.py' \
  ':!backend/app/ingest/powershell/semantic_evtx.py'

# 4. Known real personal usernames (see comment above).
for name in "${KNOWN_REAL_USERNAMES[@]:-}"; do
  [[ -z "$name" ]] && continue
  report "known real personal username '$name' outside test fixtures" \
    git grep -niI "$name" -- . "${FIXTURE_EXCLUDES[@]}"
done

if [[ "$FAILED" -eq 0 ]]; then
  echo "OK: no real infrastructure metadata found"
fi
exit "$FAILED"
