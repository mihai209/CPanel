#!/bin/bash

set -Eeuo pipefail

. /opt/cpanel-vps/scripts/common.sh

vps_load_config
vps_validate_distro
vps_detect_rootfs_arch

mkdir -p "${HOME}/.local/bin" "${ROOTFS_DIR}"

ROOTFS_URL="$(vps_rootfs_url)"
ROOTFS_FILE="$(vps_rootfs_filename)"

vps_log "INFO" "Preparing ${VPS_DISTRO} ${VPS_RELEASE} rootfs (${ROOTFS_ARCH})..." "$GREEN"
vps_log "INFO" "Downloading rootfs from ${ROOTFS_URL}" "$CYAN"

rm -f "${ROOTFS_ARCHIVE}"
curl -fL --retry 3 --connect-timeout 15 "${ROOTFS_URL}" -o "${ROOTFS_ARCHIVE}"

rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"
tar -xJf "${ROOTFS_ARCHIVE}" -C "${ROOTFS_DIR}"

mkdir -p "${ROOTFS_DIR}/root" "${ROOTFS_DIR}/home/container" "${ROOTFS_DIR}/tmp"
chmod 1777 "${ROOTFS_DIR}/tmp" || true

cat > "${ROOTFS_DIR}/etc/resolv.conf" <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

cat > "${ROOTFS_DIR}/root/.cpanel_vps_rc" <<EOF
source /tmp/cpanel-vps-common.sh
help() { vps_help; }
status() { vps_status; }
ports() { vps_ports; }
cls() { clear; }
alias vps-help='vps_help'
alias vps-status='vps_status'
alias vps-ports='vps_ports'
PS1='\[\033[0;32m\]root@\[\033[1;37m\]${VPS_HOSTNAME}\[\033[0;32m\]:\[\033[0;36m\]\w\[\033[0m\]# '
if [[ -z "\${CPANEL_VPS_BANNER_SHOWN:-}" ]]; then
    export CPANEL_VPS_BANNER_SHOWN=1
    vps_print_banner
    vps_help
fi
EOF

touch "${HOME}/.installed" "${ROOTFS_DIR}/.installed"
vps_log "INFO" "Rootfs ${ROOTFS_FILE} installed successfully." "$GREEN"
