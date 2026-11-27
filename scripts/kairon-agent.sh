#!/usr/bin/env bash
# Kairon DFIR host agent: restarts or upgrades Kairon when an administrator asks from the web UI.
#
# The containers have no access to Docker on the host, on purpose. Instead the backend writes a
# request file into ./agent/requests/ (a folder only the backend mounts, at /app/agent), and this
# agent, running on the host as the user that owns the checkout, carries out one of two fixed
# actions and writes its progress to ./agent/status/<id>.json and ./agent/logs/<id>.log:
#
#   restart  docker compose restart <backend|worker|memory-worker ...>
#   upgrade  ./scripts/dfir-backup.sh --db-only, then ./scripts/upgrade.sh
#
# Nothing else is ever run: the request names an action and services from those lists, and any
# other content is rejected. Before acting it checks again that no job is running (the backend
# checked when it accepted the request) and, for an upgrade, that the checkout has no local
# changes. ./agent/heartbeat.json tells the backend the agent is alive; the UI offers the buttons
# only then.
#
# Installed as a launchd agent (macOS) or systemd service (Linux) by scripts/host-agent.sh, which
# scripts/setup.sh runs when the "host agent" question is answered yes (KAIRON_HOST_AGENT=true).
#
# Usage: kairon-agent.sh [--once]   (--once: handle pending requests and exit; for tests)

set -uo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT_DIR="${KAIRON_ROOT_DIR:-$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)}"
AGENT_DIR="${KAIRON_AGENT_DIR:-$ROOT_DIR/agent}"
REQUESTS_DIR="$AGENT_DIR/requests"
STATUS_DIR="$AGENT_DIR/status"
LOGS_DIR="$AGENT_DIR/logs"
HEARTBEAT="$AGENT_DIR/heartbeat.json"
POLL_SECONDS="${KAIRON_AGENT_POLL_SECONDS:-2}"
AGENT_VERSION=1
ONCE=false
[[ "${1:-}" == "--once" ]] && ONCE=true

log() { printf '%s kairon-agent: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="$(printf '%s' "$value" | tr '\n\r\t' '   ')"
  printf '%s' "$value"
}

script_checksum() { cksum "$SCRIPT_PATH" 2>/dev/null | awk '{print $1}'; }

write_heartbeat() {
  local busy="$1" tmp="$HEARTBEAT.tmp.$$"
  printf '{"version": %s, "pid": %s, "seen_at": %s, "busy": "%s"}\n' "$AGENT_VERSION" "$$" "$(date +%s)" "$(json_escape "$busy")" > "$tmp" && mv -f "$tmp" "$HEARTBEAT"
}

# write_status ID ACTION STATE STEP MESSAGE [EXIT_CODE]
write_status() {
  local id="$1" action="$2" state="$3" step="$4" message="$5" code="${6:-null}" file tmp started
  file="$STATUS_DIR/$id.json"
  tmp="$file.tmp.$$"
  started="$(sed -n 's/.*"started_at": "\([^"]*\)".*/\1/p' "$file" 2>/dev/null | head -n1)"
  [[ -z "$started" ]] && started="$(now_iso)"
  local finished="null"
  case "$state" in done|failed|refused) finished="\"$(now_iso)\"" ;; esac
  printf '{"id": "%s", "action": "%s", "state": "%s", "step": "%s", "message": "%s", "exit_code": %s, "started_at": "%s", "updated_at": "%s", "finished_at": %s}\n' \
    "$id" "$action" "$state" "$step" "$(json_escape "$message")" "$code" "$started" "$(now_iso)" "$finished" > "$tmp" && mv -f "$tmp" "$file"
}

compose() { (cd "$ROOT_DIR" && docker compose "$@"); }

# Jobs queued or running in Kairon's queues, as the backend counts them. Prints a number, or
# nothing when it cannot be read (then nothing is done: unverified is not "none").
active_jobs() {
  compose exec -T backend python -m app.services.host_agent active-jobs 2>/dev/null | tail -n1 | tr -cd '0-9'
}

run_logged() {
  local logfile="$1"; shift
  printf '\n$ %s\n' "$*" >> "$logfile"
  "$@" >> "$logfile" 2>&1
}

keep_awake() {
  # macOS: a sleeping Mac pauses Docker's VM and kills long jobs; keep it awake while upgrading.
  if [[ "$(uname -s)" == "Darwin" ]] && command -v caffeinate >/dev/null 2>&1; then
    caffeinate -i "$@"
  else
    "$@"
  fi
}

do_restart() {
  local id="$1" services="$2" logfile="$LOGS_DIR/$1.log"
  write_status "$id" restart running restart "Restarting $services."
  # shellcheck disable=SC2086 # services is a validated, space-separated list
  run_logged "$logfile" compose restart $services
  local code=$?
  if [[ $code -eq 0 ]]; then
    write_status "$id" restart done restart "Restarted $services." 0
  else
    write_status "$id" restart failed restart "docker compose restart failed; see the log." "$code"
  fi
}

do_upgrade() {
  local id="$1" logfile="$LOGS_DIR/$1.log" code
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
    write_status "$id" upgrade refused checks "The Kairon directory has local changes; upgrade by hand." 1
    return
  fi
  write_status "$id" upgrade running backup "Backing up the database."
  run_logged "$logfile" keep_awake "$ROOT_DIR/scripts/dfir-backup.sh" --db-only
  code=$?
  if [[ $code -ne 0 ]]; then
    write_status "$id" upgrade failed backup "The database backup failed; nothing was upgraded." "$code"
    return
  fi
  write_status "$id" upgrade running upgrade "Pulling, rebuilding and restarting Kairon."
  KAIRON_AGENT_CHILD=1 run_logged "$logfile" keep_awake "$ROOT_DIR/scripts/upgrade.sh"
  code=$?
  if [[ $code -eq 0 ]]; then
    write_status "$id" upgrade done upgrade "Upgraded to $(git -C "$ROOT_DIR" rev-parse --short=12 HEAD 2>/dev/null)." 0
  else
    write_status "$id" upgrade failed upgrade "upgrade.sh failed; see the log. If it stopped before rebuilding, the services kept running." "$code"
  fi
}

# Reads and validates one request file. Sets REQ_ACTION and REQ_SERVICES, or returns 1.
read_request() {
  local file="$1" key value
  REQ_ACTION="" REQ_SERVICES=""
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    case "$key" in
      action) REQ_ACTION="$value" ;;
      services) REQ_SERVICES="$value" ;;
      id|requested_by|requested_at|"") ;;
      *) return 1 ;;
    esac
  done < "$file"
  case "$REQ_ACTION" in
    upgrade) REQ_SERVICES="" ;;
    restart)
      [[ -n "$REQ_SERVICES" ]] || return 1
      local service
      for service in $REQ_SERVICES; do
        case "$service" in backend|worker|memory-worker) ;; *) return 1 ;; esac
      done
      ;;
    *) return 1 ;;
  esac
  return 0
}

handle_request() {
  local file="$1" id
  id="$(basename "$file" .req)"
  [[ "$id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8,32}$ ]] || { log "ignoring badly named request $file"; return; }
  [[ -f "$STATUS_DIR/$id.json" ]] && return
  if ! read_request "$file"; then
    write_status "$id" unknown refused checks "The request is not one the agent accepts." 1
    return
  fi
  local jobs
  jobs="$(active_jobs)"
  if [[ -z "$jobs" ]]; then
    write_status "$id" "$REQ_ACTION" refused checks "Could not check Kairon's running jobs; nothing was done." 1
    return
  fi
  if [[ "$jobs" != "0" ]]; then
    write_status "$id" "$REQ_ACTION" refused checks "$jobs job(s) are queued or running; try again when they finish." 1
    return
  fi
  log "request $id: $REQ_ACTION $REQ_SERVICES"
  : > "$LOGS_DIR/$id.log"
  case "$REQ_ACTION" in
    restart) do_restart "$id" "$REQ_SERVICES" ;;
    upgrade) do_upgrade "$id" ;;
  esac
}

pending_requests() {
  local file id
  for file in "$REQUESTS_DIR"/*.req; do
    [[ -f "$file" ]] || continue
    id="$(basename "$file" .req)"
    [[ -f "$STATUS_DIR/$id.json" ]] || printf '%s\n' "$file"
  done | sort
}

main() {
  mkdir -p "$STATUS_DIR" "$LOGS_DIR" || { log "cannot write to $AGENT_DIR"; exit 1; }
  local checksum
  checksum="$(script_checksum)"
  log "started for $ROOT_DIR (pid $$)"
  while true; do
    write_heartbeat ""
    local next
    next="$(pending_requests | head -n1)"
    if [[ -n "$next" ]]; then
      local id
      id="$(basename "$next" .req)"
      # The action runs in the background so the heartbeat keeps going during a long upgrade.
      handle_request "$next" &
      local child=$!
      while kill -0 "$child" 2>/dev/null; do
        write_heartbeat "$id"
        sleep "$POLL_SECONDS"
      done
      wait "$child" 2>/dev/null
      write_heartbeat ""
      if [[ "$(script_checksum)" != "$checksum" ]]; then
        log "agent updated by the upgrade; restarting it"
        exec bash "$SCRIPT_PATH" "$@"
      fi
      continue
    fi
    $ONCE && break
    sleep "$POLL_SECONDS"
  done
}

main "$@"
