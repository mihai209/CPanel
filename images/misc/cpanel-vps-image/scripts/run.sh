#!/bin/bash

set -Eeuo pipefail

source /opt/cpanel-vps/scripts/common.sh
export HOME="${HOME:-/home/container}"
cd "$HOME"

vps_load_config
vps_validate_distro
vps_detect_rootfs_arch

if [[ ! -f "${HOME}/.installed" || ! -d "${ROOTFS_DIR}/etc" || ! -x /usr/local/bin/proot ]]; then
    /opt/cpanel-vps/scripts/install.sh
fi

cp /opt/cpanel-vps/scripts/common.sh /tmp/cpanel-vps-common.sh
chmod 644 /tmp/cpanel-vps-common.sh

exec /usr/local/bin/proot \
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
