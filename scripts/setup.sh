#!/usr/bin/env bash
set -euo pipefail

# Kairon DFIR one-command deployment script.
# Usage: bash scripts/setup.sh                 (interactive: configure + build + start)
#        bash scripts/setup.sh --non-interactive --mode lan --url http://192.0.2.10:5173
#        bash scripts/setup.sh --upgrade        (pull + rebuild + restart, preserves data)
#        bash scripts/setup.sh --validate-only
#        bash scripts/setup.sh --no-start       (configure + build only)
#        bash scripts/setup.sh --no-build       (configure + start only, warns about stale images)
#        bash scripts/setup.sh -h

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- Platform detection ----
detect_platform() {
  local os
  os="$(uname -s 2>/dev/null || echo "unknown")"

  # Detect Windows native shells (Git Bash, MSYS2, Cygwin)
  if [[ "$os" == MINGW* ]] || [[ "$os" == MSYS* ]] || [[ "$os" == CYGWIN* ]]; then
    cat >&2 <<'EOF'
Windows native shell detected.

Kairon deployment on Windows is supported through WSL2.
Please open Ubuntu/WSL2, clone the repository inside the Linux filesystem,
and run:
    ./scripts/setup.sh

Native PowerShell/CMD deployment is not supported in this beta.
EOF
    exit 3
  fi

  # Detect WSL2
  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "WSL2 detected."
    if [[ "$ROOT_DIR" == /mnt/* ]]; then
      cat >&2 <<'EOF'
WARNING: Repository is under /mnt (Windows filesystem).
This may cause performance issues, permission errors, and line-ending problems.
Recommended: clone inside the WSL Linux filesystem instead:
    cd ~ && git clone https://github.com/yokddj/kairon-dfir.git
EOF
    fi
    echo "Recommended repository location: ~/kairon-dfir"
    echo ""
    
    if ! docker info >/dev/null 2>&1; then
      cat >&2 <<'EOF'
Docker is installed but not reachable from WSL2.
Enable Docker Desktop WSL integration for this distribution,
or install Docker Engine inside WSL.
EOF
    fi
  fi

  if [[ "$os" == Darwin ]]; then
    echo "macOS detected. Docker Desktop must be installed and running."
    echo "Support is best-effort in this beta."
    echo ""
  fi
}

# ---- Configuration variables ----
DEPLOYMENT_MODE=""
PUBLIC_URL=""
AUTH_ENABLED="true"
ENABLE_MEMORY="${KAIRON_ENABLE_MEMORY:-false}"
ENABLE_DASHBOARDS="${KAIRON_ENABLE_DASHBOARDS:-false}"
BOOTSTRAP_ADMIN_USERNAME=""
BOOTSTRAP_ADMIN_EMAIL=""
INTERACTIVE=true
DO_BUILD=true
DO_START=true
DO_UPGRADE=false
FORCE_RECREATE=false
VALIDATE_ONLY=false
HEALTH_TIMEOUT="${KAIRON_HEALTH_TIMEOUT_SECONDS:-180}"

usage() {
  cat <<'EOF'
Kairon DFIR setup — configure, build and start all services.

Usage: bash scripts/setup.sh [OPTIONS]

  Run without options for interactive mode.

Options:
  --non-interactive        Run without prompts (requires --mode and --url).
  --mode MODE              Deployment mode: localhost, lan, https.
  --url URL                Public URL (e.g. http://localhost:5173).
  --memory                 Enable memory analysis feature.
  --dashboards             Enable OpenSearch Dashboards.
  --admin-user USERNAME    Bootstrap admin username.
  --admin-email EMAIL      Bootstrap admin email.
  --no-build               Skip Docker image build (warns about stale images).
  --no-start               Generate .env and build but do not start services.
  --force-recreate         Pass --force-recreate to docker compose up.
  --upgrade                Pull code, rebuild, restart — preserves all data.
  --validate-only          Validate prerequisites and .env, exit without changes.
  --debug                  Write generated secrets to stdout.
  -h, --help               Show this message.

Deployment modes:
  localhost  Single machine, browser and Kairon on the same host
  lan        Server on a trusted private network, accessed from other machines
  https      Public domain with TLS reverse proxy

Environment variables (non-interactive mode):
  KAIRON_DEPLOYMENT_MODE
  KAIRON_PUBLIC_URL
  KAIRON_ENABLE_MEMORY
  KAIRON_ENABLE_DASHBOARDS
EOF
  exit 0
}

generate_secret() {
  openssl rand -hex 32
}

check_prerequisites() {
  local missing=()
  for cmd in git docker openssl curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if ! docker compose version >/dev/null 2>&1; then
    missing+=("docker compose (v2)")
  fi

  if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "ERROR: Missing prerequisites: ${missing[*]}" >&2
    echo "Install them and re-run this script." >&2
    exit 1
  fi

  if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running or not accessible." >&2
    exit 1
  fi
}

check_ports() {
  local ports=(5173)
  for port in "${ports[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":$port " || lsof -i ":$port" >/dev/null 2>&1; then
      echo "ERROR: Port $port is already in use." >&2
      exit 1
    fi
  done
}

preserve_secrets_from_env() {
  local env_file="$1"
  if [[ ! -f "$env_file" ]]; then
    return 0
  fi

  echo "Existing .env found. Preserving existing secrets..."
  local backup_file="${env_file}.backup-$(date -u +%Y%m%dT%H%M%SZ)"
  cp "$env_file" "$backup_file"
  echo "Backup: $backup_file"

  # Read existing secrets
  KAIRON_SESSION_SECRET_EXISTING=$(grep '^KAIRON_SESSION_SECRET=' "$env_file" | sed 's/^KAIRON_SESSION_SECRET=//' || echo "")
  KAIRON_CSRF_SECRET_EXISTING=$(grep '^KAIRON_CSRF_SECRET=' "$env_file" | sed 's/^KAIRON_CSRF_SECRET=//' || echo "")
  POSTGRES_PASSWORD_EXISTING=$(grep '^POSTGRES_PASSWORD=' "$env_file" | sed 's/^POSTGRES_PASSWORD=//' || echo "")
  OPENSEARCH_INITIAL_ADMIN_PASSWORD_EXISTING=$(grep '^OPENSEARCH_INITIAL_ADMIN_PASSWORD=' "$env_file" | sed 's/^OPENSEARCH_INITIAL_ADMIN_PASSWORD=//' || echo "")

  # Read existing feature flags
  ENABLE_MEMORY_EXISTING=$(grep '^KAIRON_ENABLE_MEMORY=' "$env_file" | sed 's/^KAIRON_ENABLE_MEMORY=//' || echo "false")
  ENABLE_DASHBOARDS_EXISTING=$(grep '^KAIRON_ENABLE_DASHBOARDS=' "$env_file" | sed 's/^KAIRON_ENABLE_DASHBOARDS=//' || echo "false")

  # Preserved across runs so the host directories' group ownership (set by
  # prepare_memory_storage_permissions.sh) and docker-compose's
  # `group_add:` for the memory containers always agree on the same GID.
  MEMORY_EVIDENCE_SHARED_GID_EXISTING=$(grep '^MEMORY_EVIDENCE_SHARED_GID=' "$env_file" | sed 's/^MEMORY_EVIDENCE_SHARED_GID=//' || echo "")

  export KAIRON_SESSION_SECRET_EXISTING
  export KAIRON_CSRF_SECRET_EXISTING
  export POSTGRES_PASSWORD_EXISTING
  export OPENSEARCH_INITIAL_ADMIN_PASSWORD_EXISTING
  export MEMORY_EVIDENCE_SHARED_GID_EXISTING
  [[ -n "$ENABLE_MEMORY_EXISTING" ]] && ENABLE_MEMORY="$ENABLE_MEMORY_EXISTING"
  [[ -n "$ENABLE_DASHBOARDS_EXISTING" ]] && ENABLE_DASHBOARDS="$ENABLE_DASHBOARDS_EXISTING"
}

write_env() {
  local env_file="$ROOT_DIR/.env"
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local derived_url="$PUBLIC_URL"
  local derived_dashboards_url="http://localhost:5601"
  if [[ -z "$derived_url" ]]; then
    case "$DEPLOYMENT_MODE" in
      localhost) derived_url="http://localhost:5173" ;;
      lan)       derived_url="http://localhost:5173" ;;
      https)     derived_url="https://localhost" ;;
      *)         derived_url="http://localhost:5173" ;;
    esac
  fi

  if [[ "$DEPLOYMENT_MODE" == "https" ]]; then
    derived_url="${derived_url%/}"
    if [[ ! "$derived_url" =~ ^https:// ]]; then
      echo "WARNING: HTTPS mode selected but URL does not start with https://" >&2
    fi
  fi

  # Use preserved secrets if available, otherwise generate new
  local session_secret="${KAIRON_SESSION_SECRET_EXISTING:-$(generate_secret)}"
  local csrf_secret="${KAIRON_CSRF_SECRET_EXISTING:-$(generate_secret)}"
  local postgres_pwd="${POSTGRES_PASSWORD_EXISTING:-$(generate_secret)}"
  local opensearch_pwd="${OPENSEARCH_INITIAL_ADMIN_PASSWORD_EXISTING:-$(generate_secret)}"

  # Resolved once and reused for both the host directory's group (see
  # prepare_memory_storage_permissions.sh) and docker-compose's
  # `group_add:` for the memory containers. Defaults to the current host
  # user's own primary group, which they can always chgrp their own
  # directories to without sudo -- never a hardcoded container-internal
  # GID, which would require elevated privilege to apply on the host.
  # SUDO_GID (set automatically by sudo) takes precedence over `id -g` so
  # that running this whole script with sudo still resolves the real
  # invoking user's group instead of root's.
  local memory_shared_gid="${MEMORY_EVIDENCE_SHARED_GID_EXISTING:-${SUDO_GID:-$(id -g)}}"

  echo "# Kairon DFIR environment — generated by scripts/setup.sh at ${timestamp}" > "$env_file"
  echo "# Deployment mode: ${DEPLOYMENT_MODE}" >> "$env_file"
  echo "" >> "$env_file"

  cat >> "$env_file" <<-ENVEOF
KAIRON_DEPLOYMENT_MODE=${DEPLOYMENT_MODE}
KAIRON_PUBLIC_URL=${derived_url}
KAIRON_AUTH_ENABLED=${AUTH_ENABLED}

# ---- Secrets ----
KAIRON_SESSION_SECRET=${session_secret}
KAIRON_CSRF_SECRET=${csrf_secret}
POSTGRES_PASSWORD=${postgres_pwd}
OPENSEARCH_INITIAL_ADMIN_PASSWORD=${opensearch_pwd}

# ---- Optional bootstrap admin (prefer web wizard) ----
KAIRON_BOOTSTRAP_ADMIN_USERNAME=${BOOTSTRAP_ADMIN_USERNAME}
KAIRON_BOOTSTRAP_ADMIN_EMAIL=${BOOTSTRAP_ADMIN_EMAIL}
KAIRON_BOOTSTRAP_ADMIN_PASSWORD=

# ---- Optional features ----
KAIRON_ENABLE_MEMORY=${ENABLE_MEMORY}
KAIRON_ENABLE_DASHBOARDS=${ENABLE_DASHBOARDS}
MEMORY_ANALYSIS_ENABLED=${ENABLE_MEMORY}
MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=${ENABLE_MEMORY}
MEMORY_UPLOAD_ENABLED=${ENABLE_MEMORY}
MEMORY_UPLOAD_MIN_FREE_SPACE_BYTES=5368709120
MEMORY_WORKER_MODE=dedicated_worker
MEMORY_EVIDENCE_SHARED_GID=${memory_shared_gid}
MEMORY_PROCESS_PROFILE_ENABLED=${ENABLE_MEMORY}
MEMORY_ALLOWED_PROFILES=metadata_only,processes_basic,processes_extended,network_basic,modules_basic,handles_basic,kernel_basic,suspicious_memory,shell_history_basic
MEMORY_ALLOWED_PLUGINS=windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,windows.envars,windows.getsids,windows.privileges,windows.netscan,windows.netstat,windows.dlllist,windows.ldrmodules,windows.handles,windows.modules,windows.driverscan,windows.malfind,windows.vadinfo,linux.pslist,linux.pstree,linux.sockstat,linux.bash

# ---- Advanced overrides (see config/defaults.env for all defaults) ----
# POSTGRES_HOST=postgres
# REDIS_URL=redis://redis:6379/0
# BACKEND_LOG_LEVEL=INFO
ENVEOF

  chmod 600 "$env_file"

  echo ""
  echo "=== .env file written ==="
  echo "  Path:  $env_file"
  echo "  Mode:  $DEPLOYMENT_MODE"
  echo "  URL:   $derived_url"
  echo "  Auth:  $AUTH_ENABLED"
  echo "  Memory:  $ENABLE_MEMORY"
  echo "  Dashboards:  $ENABLE_DASHBOARDS"
}

build_and_start() {
  echo ""
  echo "=== Building Docker images ==="
  local compose_args=()
  [[ "$ENABLE_MEMORY" == true ]] && compose_args+=(--profile memory)
  [[ "$ENABLE_DASHBOARDS" == true ]] && compose_args+=(--profile dashboards)

  if [[ "$ENABLE_MEMORY" == true ]]; then
    echo "Preparing memory storage permissions..."
    # Read back the exact GID write_env() just resolved and wrote to
    # .env, so this never derives its own (potentially different) value
    # -- it must match what docker-compose's group_add: will use.
    local shared_gid
    shared_gid=$(grep '^MEMORY_EVIDENCE_SHARED_GID=' "$ROOT_DIR/.env" | sed 's/^MEMORY_EVIDENCE_SHARED_GID=//')
    MEMORY_EVIDENCE_SHARED_GID="$shared_gid" \
      MEMORY_EVIDENCE_HOST_ROOT="$ROOT_DIR/data/evidence" \
      MEMORY_OUTPUT_HOST_ROOT="$ROOT_DIR/data/memory-output" \
      sh "$SCRIPT_DIR/prepare_memory_storage_permissions.sh"
  fi

  local build_args=(--pull)
  if [[ "$FORCE_RECREATE" == true ]] || [[ "$DO_UPGRADE" == true ]]; then
    build_args=(--no-cache --pull)
  fi
  docker compose "${compose_args[@]}" build "${build_args[@]}"
  echo "Build complete."

  if [[ "$DO_START" != true ]]; then
    echo "Services not started (--no-start)."
    return
  fi

  echo ""
  echo "=== Starting services ==="
  local up_args=(-d)
  if [[ "$FORCE_RECREATE" == true ]] || [[ "$DO_UPGRADE" == true ]]; then
    up_args+=(--force-recreate)
  fi
  docker compose "${compose_args[@]}" up "${up_args[@]}"

  wait_for_health
}

wait_for_health() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  local backend_ok=false
  local frontend_ok=false
  local version=""

  echo ""
  echo "=== Waiting for services (timeout: ${HEALTH_TIMEOUT}s) ==="
  
  while [[ $SECONDS -lt $deadline ]]; do
    if [[ "$backend_ok" != true ]]; then
      if version=$(curl -s -m 5 http://localhost:8000/api/system/version 2>/dev/null); then
        echo "Backend: healthy"
        backend_ok=true
      fi
    fi

    if [[ "$frontend_ok" != true ]]; then
      if curl -s -o /dev/null -m 5 http://localhost:5173 2>/dev/null; then
        echo "Frontend: healthy"
        frontend_ok=true
      fi
    fi

    if [[ "$backend_ok" == true ]] && [[ "$frontend_ok" == true ]]; then
      break
    fi
    sleep 3
  done

  if [[ "$backend_ok" != true ]]; then
    echo "WARNING: Backend did not respond in time."
    echo "Check logs: docker compose logs --tail=50 backend"
  fi
  if [[ "$frontend_ok" != true ]]; then
    echo "WARNING: Frontend did not respond in time."
    echo "Check logs: docker compose logs --tail=50 frontend"
  fi
}

show_planned_actions() {
  local env_file="$ROOT_DIR/.env"
  local has_env="no"
  local has_data="unknown"
  [[ -f "$env_file" ]] && has_env="yes"
  if docker compose ps --format '{{.Name}}' 2>/dev/null | grep -q .; then
    has_data="yes (containers running)"
  fi

  local profiles="none"
  [[ "$ENABLE_MEMORY" == true ]] && profiles="memory"
  [[ "$ENABLE_DASHBOARDS" == true ]] && profiles="${profiles:+$profiles,}dashboards"
  [[ -z "$profiles" ]] && profiles="none"

  echo ""
  echo "=== Planned actions ==="
  echo "  Write/update .env:      $([[ "$has_env" == no ]] && echo yes || echo 'yes (secrets preserved)')"
  echo "  Build images:           $([[ "$DO_BUILD" == true ]] && echo yes || echo no)"
  echo "  Start services:         $([[ "$DO_START" == true ]] && echo yes || echo no)"
  echo "  Force recreate:         $([[ "$FORCE_RECREATE" == true ]] && echo yes || echo no)"
  echo "  Compose profiles:       $profiles"
  echo "  Public URL:             ${PUBLIC_URL:-auto}"
  echo "  Existing .env:          $has_env"
  echo "  Existing containers:    $has_data"
  echo "  Destructive actions:    no"
  echo "================================"
  echo ""
}

show_final_output() {
  local derived_url="${PUBLIC_URL:-http://localhost:5173}"
  echo ""
  echo "============================================"
  echo "  Kairon DFIR is running."
  echo "  URL:  $derived_url"
  echo ""

  local needs_setup="unknown"
  if needs_setup=$(curl -s -m 5 "${derived_url}/api/auth/needs-setup" 2>/dev/null); then
    if echo "$needs_setup" | grep -q '"needs_setup":true'; then
      echo "  First administrator wizard: YES"
      echo "  Open the URL in your browser and create the admin account."
      echo ""
    elif echo "$needs_setup" | grep -q '"needs_setup":false'; then
      echo "  Users already exist. Sign in with an existing account."
      echo ""
    fi
  fi

  echo "  Useful commands:"
  echo "    docker compose ps"
  echo "    docker compose logs --tail=100 backend"
  echo "    docker compose logs --tail=100 frontend"

  if [[ "$AUTH_ENABLED" == true ]]; then
    echo "    docker compose exec postgres psql -U dfir -d dfir -c \"SELECT username, is_admin, is_active FROM users;\""
  fi

  if [[ "$ENABLE_MEMORY" == true ]]; then
    echo ""
    echo "  Memory analysis profile:"
    echo "    docker compose --profile memory build --pull"
    echo "    docker compose --profile memory up -d"
  fi

  if [[ "$ENABLE_DASHBOARDS" == true ]]; then
    echo ""
    echo "  Dashboards: http://localhost:5601"
  fi
  echo "============================================"
}

interactive_mode() {
  echo "=== Kairon DFIR First-Run Setup ==="
  echo ""

  echo "Select deployment mode:"
  echo "  1) localhost — single developer machine (default)"
  echo "  2) lan — local network access from other machines"
  echo "  3) https — production with HTTPS reverse proxy"
  read -r -p "Choice [1]: " mode_choice
  case "${mode_choice:-1}" in
    1) DEPLOYMENT_MODE="localhost" ;;
    2) DEPLOYMENT_MODE="lan" ;;
    3) DEPLOYMENT_MODE="https" ;;
    *) DEPLOYMENT_MODE="localhost" ;;
  esac
  echo "  Selected: $DEPLOYMENT_MODE"
  echo ""

  local default_url
  case "$DEPLOYMENT_MODE" in
    localhost) default_url="http://localhost:5173" ;;
    lan)       default_url="http://localhost:5173" ;;
    https)     default_url="https://localhost" ;;
  esac
  if [[ "$DEPLOYMENT_MODE" == "lan" ]]; then
    read -r -p "Public URL (e.g. http://192.0.2.10:5173) [$default_url]: " url_input
  else
    read -r -p "Public URL [$default_url]: " url_input
  fi
  PUBLIC_URL="${url_input:-$default_url}"
  echo "  Public URL: $PUBLIC_URL"
  echo ""

  AUTH_ENABLED="true"
  echo "  Authentication: true (required)"
  echo ""

  read -r -p "Enable memory analysis? [y/N]: " mem_input
  case "${mem_input:-n}" in
    [Yy]*) ENABLE_MEMORY="true" ;;
    *)    ENABLE_MEMORY="false" ;;
  esac
  echo "  Memory analysis: $ENABLE_MEMORY"
  echo ""

  read -r -p "Enable OpenSearch Dashboards? [y/N]: " dash_input
  case "${dash_input:-n}" in
    [Yy]*) ENABLE_DASHBOARDS="true" ;;
    *)    ENABLE_DASHBOARDS="false" ;;
  esac
  echo "  Dashboards: $ENABLE_DASHBOARDS"
  echo ""

  echo "=== Configuration summary ==="
  echo "  Mode:  $DEPLOYMENT_MODE"
  echo "  URL:   $PUBLIC_URL"
  echo "  Auth:  $AUTH_ENABLED"
  echo "  Memory: $ENABLE_MEMORY"
  echo "  Dashboards: $ENABLE_DASHBOARDS"
  echo ""

  if [[ "$DEPLOYMENT_MODE" == "lan" ]]; then
    echo "WARNING: LAN mode uses HTTP. Do not expose it to untrusted networks."
    echo ""
  fi

  read -r -p "Build and start services now? [Y/n]: " start_input
  case "${start_input:-y}" in
    [Nn]*) DO_START=false ;;
    *)     DO_START=true ;;
  esac
  echo ""
}

non_interactive_mode() {
  if [[ -z "$DEPLOYMENT_MODE" ]]; then
    echo "ERROR: --mode is required in non-interactive mode." >&2
    echo "Valid modes: localhost, lan, https" >&2
    exit 2
  fi

  case "$DEPLOYMENT_MODE" in
    localhost|lan|https) ;;
    *)
      echo "ERROR: Invalid deployment mode '$DEPLOYMENT_MODE'." >&2
      exit 2
      ;;
  esac
}

check_existing_env() {
  local env_file="$ROOT_DIR/.env"
  if [[ -f "$env_file" ]]; then
    echo "NOTE: $env_file already exists. Secrets will be preserved."
    if [[ "$INTERACTIVE" == true ]]; then
      read -r -p "Regenerate configuration? [y/N]: " regen
      case "${regen:-n}" in
        [Yy]*) 
          echo "WARNING: Regenerating configuration will create new secrets."
          read -r -p "Type 'REGENERATE' to confirm: " confirm
          if [[ "$confirm" != "REGENERATE" ]]; then
            echo "Keeping existing secrets. Configuration updated."
            preserve_secrets_from_env "$env_file"
            return 0
          fi
          ;;
        *) 
          preserve_secrets_from_env "$env_file"
          return 0
          ;;
      esac
    else
      preserve_secrets_from_env "$env_file"
    fi
  fi
}

do_upgrade() {
  echo "=== Kairon DFIR Upgrade ==="
  echo ""
  
  if [[ ! -f "$ROOT_DIR/.env" ]]; then
    echo "ERROR: No .env found. Run './scripts/setup.sh' first." >&2
    exit 1
  fi

  preserve_secrets_from_env "$ROOT_DIR/.env"
  
  echo ""
  echo "Pulling latest code..."
  git -C "$ROOT_DIR" pull 2>&1 || echo "WARNING: git pull failed. Continuing with local code."
  echo ""

  echo "Rebuilding and restarting services..."
  FORCE_RECREATE=true
  DO_BUILD=true
  DO_START=true
  build_and_start
  show_final_output
  exit 0
}

# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) INTERACTIVE=false; shift ;;
    --mode) DEPLOYMENT_MODE="$2"; shift 2 ;;
    --url) PUBLIC_URL="$2"; shift 2 ;;
    --no-auth)
      echo "ERROR: authentication is required and cannot be disabled." >&2
      exit 2
      ;;
    --memory) ENABLE_MEMORY="true"; shift ;;
    --dashboards) ENABLE_DASHBOARDS="true"; shift ;;
    --admin-user) BOOTSTRAP_ADMIN_USERNAME="$2"; shift 2 ;;
    --admin-email) BOOTSTRAP_ADMIN_EMAIL="$2"; shift 2 ;;
    --no-build) DO_BUILD=false; shift ;;
    --no-start) DO_START=false; shift ;;
    --force-recreate) FORCE_RECREATE=true; shift ;;
    --upgrade) DO_UPGRADE=true; shift ;;
    --validate-only) VALIDATE_ONLY=true; shift ;;
    --debug)
      echo "=== Debug: secrets will NOT be generated ==="
      generate_secret() { echo "DEBUG_SECRET_$(openssl rand -hex 4)"; }
      shift
      ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# ---- Platform check ----
detect_platform

# ---- Upgrade path ----
if [[ "$DO_UPGRADE" == true ]]; then
  check_prerequisites
  do_upgrade
fi

# ---- Validate only ----
if [[ "$VALIDATE_ONLY" == true ]]; then
  check_prerequisites
  if [[ -f "$ROOT_DIR/.env" ]]; then
    echo ".env exists."
    "$SCRIPT_DIR/validate-config.sh" || true
  else
    echo "WARNING: .env not found. Run './scripts/setup.sh' first." >&2
    exit 1
  fi
  echo "Validate-only: no changes made."
  exit 0
fi

# ---- Normal flow ----
check_prerequisites

if [[ "$INTERACTIVE" == true ]]; then
  check_existing_env
  interactive_mode
else
  check_existing_env
  non_interactive_mode
fi

show_planned_actions
write_env

if [[ "$DO_BUILD" != true ]]; then
  if [[ "$DO_UPGRADE" != true ]]; then
    cat >&2 <<'EOF'
WARNING: --no-build may reuse stale Docker images.
Use this only if you know the images are already up to date.
EOF
  fi
fi

if [[ "$DO_BUILD" == true ]] || [[ "$DO_START" == true ]]; then
  build_and_start
  if [[ "$DO_START" == true ]]; then
    show_final_output
  fi
fi
