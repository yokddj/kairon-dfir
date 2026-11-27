#!/usr/bin/env bash
# Installs, removes or shows the Kairon DFIR host agent (scripts/kairon-agent.sh), which lets an
# administrator restart or upgrade Kairon from the web UI.
#
#   scripts/host-agent.sh configure   install or remove it as KAIRON_HOST_AGENT in .env says
#   scripts/host-agent.sh enable      set KAIRON_HOST_AGENT=true in .env and install it
#   scripts/host-agent.sh disable     set KAIRON_HOST_AGENT=false in .env and remove it
#   scripts/host-agent.sh status
#
# macOS: a launchd agent of the current user (~/Library/LaunchAgents/com.kairon-dfir.agent.plist).
# Linux: a systemd service; a system unit when run as root, otherwise a user unit (which needs
# `loginctl enable-linger` to keep running after logout).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
AGENT_SCRIPT="$ROOT_DIR/scripts/kairon-agent.sh"
AGENT_DIR="$ROOT_DIR/agent"
LABEL="com.kairon-dfir.agent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
UNIT_NAME="kairon-agent.service"
AGENT_PATH="/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin"

env_value() {
  [[ -f "$ENV_FILE" ]] || return 0
  grep '^KAIRON_HOST_AGENT=' "$ENV_FILE" | tail -n1 | sed 's/^KAIRON_HOST_AGENT=//' || true
}

set_env_value() {
  local value="$1" tmp
  [[ -f "$ENV_FILE" ]] || { echo "No .env: run scripts/setup.sh first." >&2; exit 1; }
  tmp="$(mktemp)"
  grep -v '^KAIRON_HOST_AGENT=' "$ENV_FILE" > "$tmp" || true
  printf 'KAIRON_HOST_AGENT=%s\n' "$value" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

prepare_dirs() {
  mkdir -p "$AGENT_DIR/requests" "$AGENT_DIR/status" "$AGENT_DIR/logs"
  if [[ ! -w "$AGENT_DIR/status" ]]; then
    echo "ERROR: $AGENT_DIR is not writable by $(id -un) (docker may have created it as root)." >&2
    echo "Fix it with: sudo chown -R $(id -un) \"$AGENT_DIR\"" >&2
    exit 1
  fi
}

systemd_scope() { [[ "$(id -u)" == "0" ]] && echo system || echo user; }

unit_path() {
  if [[ "$(systemd_scope)" == system ]]; then
    echo "/etc/systemd/system/$UNIT_NAME"
  else
    echo "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT_NAME"
  fi
}

systemctl_scoped() {
  if [[ "$(systemd_scope)" == system ]]; then systemctl "$@"; else systemctl --user "$@"; fi
}

install_macos() {
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$AGENT_SCRIPT</string></array>
  <key>WorkingDirectory</key><string>$ROOT_DIR</string>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>$AGENT_PATH</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$AGENT_DIR/agent.log</string>
  <key>StandardErrorPath</key><string>$AGENT_DIR/agent.log</string>
</dict>
</plist>
EOF
  mkdir -p "$(dirname "$PLIST")"
  local domain="gui/$(id -u)"
  if [[ -f "$PLIST" ]] && cmp -s "$tmp" "$PLIST" && launchctl print "$domain/$LABEL" >/dev/null 2>&1; then
    rm -f "$tmp"
    echo "Host agent: already installed and running (launchd $LABEL)."
    return
  fi
  launchctl bootout "$domain/$LABEL" >/dev/null 2>&1 || true
  mv -f "$tmp" "$PLIST"
  launchctl bootstrap "$domain" "$PLIST"
  echo "Host agent: installed (launchd $LABEL)."
}

uninstall_macos() {
  launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
  if [[ -f "$PLIST" ]]; then
    rm -f "$PLIST"
    echo "Host agent: removed."
  fi
}

install_linux() {
  command -v systemctl >/dev/null 2>&1 || { echo "ERROR: systemd not found; run scripts/kairon-agent.sh under your own supervisor." >&2; exit 1; }
  local unit tmp wanted
  unit="$(unit_path)"
  wanted="default.target"
  [[ "$(systemd_scope)" == system ]] && wanted="multi-user.target"
  tmp="$(mktemp)"
  cat > "$tmp" <<EOF
[Unit]
Description=Kairon DFIR host agent (restart and upgrade from the web UI)
After=docker.service

[Service]
ExecStart=/bin/bash $AGENT_SCRIPT
WorkingDirectory=$ROOT_DIR
Environment=PATH=$AGENT_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=$wanted
EOF
  mkdir -p "$(dirname "$unit")"
  if [[ -f "$unit" ]] && cmp -s "$tmp" "$unit" && systemctl_scoped is-active --quiet "$UNIT_NAME"; then
    rm -f "$tmp"
    echo "Host agent: already installed and running (systemd $(systemd_scope) $UNIT_NAME)."
    return
  fi
  mv -f "$tmp" "$unit"
  systemctl_scoped daemon-reload
  systemctl_scoped enable --now "$UNIT_NAME"
  systemctl_scoped restart "$UNIT_NAME"
  echo "Host agent: installed (systemd $(systemd_scope) $UNIT_NAME)."
  if [[ "$(systemd_scope)" == user ]] && ! loginctl show-user "$(id -un)" -p Linger 2>/dev/null | grep -q 'yes'; then
    echo "NOTE: to keep the agent running after you log out, run: sudo loginctl enable-linger $(id -un)"
  fi
}

uninstall_linux() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local unit
  unit="$(unit_path)"
  if [[ -f "$unit" ]]; then
    systemctl_scoped disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$unit"
    systemctl_scoped daemon-reload || true
    echo "Host agent: removed."
  fi
}

install_agent() {
  prepare_dirs
  case "$(uname -s)" in
    Darwin) install_macos ;;
    Linux) install_linux ;;
    *) echo "ERROR: the host agent supports macOS and Linux." >&2; exit 1 ;;
  esac
}

uninstall_agent() {
  case "$(uname -s)" in
    Darwin) uninstall_macos ;;
    Linux) uninstall_linux ;;
  esac
}

show_status() {
  echo "KAIRON_HOST_AGENT in .env: $(env_value || true)"
  if [[ -f "$AGENT_DIR/heartbeat.json" ]]; then
    echo "Last heartbeat: $(cat "$AGENT_DIR/heartbeat.json")"
  else
    echo "No heartbeat yet."
  fi
}

case "${1:-}" in
  configure)
    # An upgrade run by the agent itself must not reload the agent under its own feet.
    if [[ "${KAIRON_AGENT_CHILD:-}" == "1" ]]; then
      exit 0
    fi
    if [[ "$(env_value)" == "true" ]]; then install_agent; else uninstall_agent; fi
    ;;
  enable) set_env_value true; install_agent ;;
  disable) set_env_value false; uninstall_agent ;;
  status) show_status ;;
  *) echo "Usage: $0 configure|enable|disable|status" >&2; exit 2 ;;
esac
