#!/bin/bash

set -Eeuo pipefail

source /opt/cpanel-vps/scripts/common.sh
export HOME="${HOME:-/home/container}"
cd "$HOME"

vps_load_config
vps_validate_distro
vps_detect_rootfs_arch

PROOT_BIN="$(command -v proot || true)"
if [[ -z "${PROOT_BIN}" ]]; then
    vps_log "ERROR" "proot is not installed in this image." "$RED" >&2
    exit 1
fi

PROOT_VERSION_LINE="$("${PROOT_BIN}" --version 2>&1 | head -n 1 || true)"
if [[ -n "${PROOT_VERSION_LINE}" ]]; then
    vps_log "INFO" "Using ${PROOT_VERSION_LINE}" "$CYAN"
fi

if [[ ! -f "${HOME}/.installed" || ! -d "${ROOTFS_DIR}/etc" ]]; then
    /opt/cpanel-vps/scripts/install.sh
fi

cp /opt/cpanel-vps/scripts/common.sh /tmp/cpanel-vps-common.sh
chmod 644 /tmp/cpanel-vps-common.sh

exec "${PROOT_BIN}" \
    --rootfs="${ROOTFS_DIR}" \
    -0 \
    -w /root \
    -b /dev \
    -b /sys \
    -b /proc \
    -b /tmp:/tmp \
    -b "${HOME}:/home/container" \
    -b /opt/cpanel-vps/scripts:/opt/cpanel-vps/scripts \
    /bin/bash --rcfile /root/.cpanel_vps_rc -i
