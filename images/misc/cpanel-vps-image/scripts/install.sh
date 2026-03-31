#!/bin/bash

set -Eeuo pipefail

. /opt/cpanel-vps/scripts/common.sh

mkdir -p "${HOME}/.local/bin"
touch "${HOME}/.installed"

vps_log "INFO" "Base VPS runtime is ready. No nested image download is required." "$GREEN"
