#!/bin/bash
# install.sh - LinkGuard FW installation script
# Usage: sudo bash install.sh
set -euo pipefail

BINARY_NAME="linkguard-fw"
INSTALL_BIN="/usr/local/bin/${BINARY_NAME}"
CONFIG_DIR="/etc/linkguard-fw"
DATA_DIR="/var/lib/linkguard-fw"
SERVICE_FILE="/etc/systemd/system/${BINARY_NAME}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        error "This script must be run as root. Use: sudo bash install.sh"
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || error "Required command not found: $1"
}

# ─── Checks ──────────────────────────────────────────────────────────────────

require_root
require_cmd systemctl

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "Detected OS: ${PRETTY_NAME:-unknown}"
else
    warn "Could not detect OS. Continuing anyway."
fi

# ─── Install binary ──────────────────────────────────────────────────────────

BINARY_SRC="${SCRIPT_DIR}/../dist/${BINARY_NAME}"
if [[ ! -f "${BINARY_SRC}" ]]; then
    BINARY_SRC="${SCRIPT_DIR}/${BINARY_NAME}"
fi
if [[ ! -f "${BINARY_SRC}" ]]; then
    error "Binary not found. Build the project first with: make build"
fi

info "Installing binary to ${INSTALL_BIN}..."
install -m 0755 "${BINARY_SRC}" "${INSTALL_BIN}"

# ─── Prepare the filesystem the systemd unit needs ───────────────────────────
#
# Mesma chamada que o postinst do .deb e o `make install` fazem, para que os
# três caminhos de instalação deixem a máquina no MESMO estado. A lista de
# caminhos mora em internal/sysprep (um lugar só).
#
# Sem isto, instalar por este script deixava o serviço em loop de
# 226/NAMESPACE ("Failed to set up mount namespacing: /etc/nftables.conf: No
# such file or directory") — e cada tentativa disparava o
# OnFailure=linkguard-notify-down.service.

info "Preparing system paths (nftables.conf, config/state dirs, DHCP/DNS dirs)..."
"${INSTALL_BIN}" --prepare-system

# ─── Default config ──────────────────────────────────────────────────────────

if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
    info "Generating default configuration..."

    # Generate a random JWT secret (64 chars) so the service is not
    # accidentally started with an empty/insecure secret.
    JWT_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 64 || true)
    if [[ -z "${JWT_SECRET}" ]]; then
        JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | head -c 64)
    fi

    cat > "${CONFIG_DIR}/config.json" << EOF
{
  "listen_addr": "127.0.0.1",
  "port": 9997,
  "db_path": "/var/lib/linkguard-fw/linkguard.db",
  "jwt_secret": "${JWT_SECRET}",
  "dry_run": false,
  "debug": false,
  "monitor_interval_seconds": 30,
  "failover_enabled": true,
  "failover_threshold": 3,
  "recovery_threshold": 2,
  "failover_cooldown_seconds": 60,
  "metrics_enabled": true
}
EOF
    chmod 640 "${CONFIG_DIR}/config.json"
    info "Config file created at ${CONFIG_DIR}/config.json"
    info "jwt_secret gerado automaticamente."
else
    info "Config file already exists at ${CONFIG_DIR}/config.json — skipping."
fi

# ─── Install systemd service ─────────────────────────────────────────────────

SERVICE_SRC="${SCRIPT_DIR}/linkguard-fw.service"
if [[ ! -f "${SERVICE_SRC}" ]]; then
    SERVICE_SRC="${SCRIPT_DIR}/../deploy/linkguard-fw.service"
fi

if [[ -f "${SERVICE_SRC}" ]]; then
    info "Installing systemd service..."
    install -m 0644 "${SERVICE_SRC}" "${SERVICE_FILE}"
    systemctl daemon-reload
else
    warn "Service file not found. Skipping systemd installation."
fi

# ─── Done ────────────────────────────────────────────────────────────────────

info ""
info "LinkGuard FW installed successfully!"
info ""
info "Next steps:"
info "  1. Edit the config:  nano ${CONFIG_DIR}/config.json"
info "     - 'jwt_secret' was generated automatically; no action needed"
info "     - Set 'listen_addr' (127.0.0.1 for local, or a specific IP)"
info "     - Set 'dry_run: false' when ready to apply firewall changes"
info ""
info "  2. Enable and start the service:"
info "     systemctl enable --now linkguard-fw"
info ""
info "  3. Access the web interface:"
info "     http://127.0.0.1:9997  (or the configured address)"
info "     Default login: admin / admin"
info "     CHANGE THE PASSWORD IMMEDIATELY after first login!"
info ""
info "  4. Check service status:"
info "     systemctl status linkguard-fw"
info "     journalctl -u linkguard-fw -f"
