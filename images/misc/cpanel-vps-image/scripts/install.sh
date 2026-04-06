#!/bin/bash

set -Eeuo pipefail

. /opt/cpanel-vps/scripts/common.sh

vps_load_config
vps_validate_distro
vps_detect_rootfs_arch

mkdir -p "${HOME}/.local/bin" "${ROOTFS_DIR}"

ROOTFS_FILE="$(vps_rootfs_filename)"
ROOTFS_URLS=()
ROOTFS_URLS+=("$(vps_rootfs_url)")
if [[ -n "${ROOTFS_FALLBACK_TAG}" && "${ROOTFS_FALLBACK_TAG}" != "${ROOTFS_TAG}" ]]; then
    ROOTFS_URLS+=("$(vps_rootfs_url_for_tag "${ROOTFS_FALLBACK_TAG}")")
fi

vps_log "INFO" "Preparing ${VPS_DISTRO} ${VPS_RELEASE} rootfs (${ROOTFS_ARCH})..." "$GREEN"
vps_log "INFO" "Target filesystem tree will be created under ${ROOTFS_DIR}" "$CYAN"

rm -f "${ROOTFS_ARCHIVE}"

downloaded_url=""

for candidate_url in "${ROOTFS_URLS[@]}"; do
    vps_log "INFO" "Trying rootfs source ${candidate_url}" "$CYAN"

    # 🔴 Local file handling (file://)
    if [[ "${candidate_url}" == file://* ]]; then
        LOCAL_PATH="${candidate_url#file://}"
        vps_log "INFO" "Using local file ${LOCAL_PATH}" "$CYAN"

        if [[ -f "${LOCAL_PATH}" ]]; then
            cp "${LOCAL_PATH}" "${ROOTFS_ARCHIVE}.tmp"
            mv "${ROOTFS_ARCHIVE}.tmp" "${ROOTFS_ARCHIVE}"
            downloaded_url="${candidate_url}"
            break
        else
            vps_log "WARN" "Local rootfs not found: ${LOCAL_PATH}" "$YELLOW"
            continue
        fi
    fi

    # 🔴 Remote download
    if command -v wget >/dev/null 2>&1; then
        if wget --tries=3 --timeout=15 --show-progress --progress=bar:force:noscroll -O "${ROOTFS_ARCHIVE}.tmp" "${candidate_url}"; then
            mv "${ROOTFS_ARCHIVE}.tmp" "${ROOTFS_ARCHIVE}"
            downloaded_url="${candidate_url}"
            break
        fi
    elif command -v curl >/dev/null 2>&1; then
        if curl -fL --retry 3 --connect-timeout 15 --progress-bar "${candidate_url}" -o "${ROOTFS_ARCHIVE}.tmp"; then
            mv "${ROOTFS_ARCHIVE}.tmp" "${ROOTFS_ARCHIVE}"
            downloaded_url="${candidate_url}"
            break
        fi
    else
        vps_log "ERROR" "Neither wget nor curl is available." "$RED" >&2
        exit 1
    fi

    rm -f "${ROOTFS_ARCHIVE}.tmp"
    vps_log "WARN" "Rootfs download failed from ${candidate_url}" "$YELLOW"
done

if [[ -z "${downloaded_url}" || ! -s "${ROOTFS_ARCHIVE}" ]]; then
    vps_log "ERROR" "No rootfs archive could be downloaded." "$RED" >&2
    vps_log "ERROR" "Expected file: ${ROOTFS_FILE}" "$RED" >&2
    vps_log "ERROR" "Checked base URL: ${ROOTFS_BASE_URL}" "$RED" >&2
    vps_log "ERROR" "Primary tag: ${ROOTFS_TAG} | Fallback tag: ${ROOTFS_FALLBACK_TAG}" "$RED" >&2
    exit 1
fi

vps_log "INFO" "Using rootfs archive from ${downloaded_url}" "$GREEN"
vps_log "INFO" "Extracting ${ROOTFS_FILE}..." "$CYAN"

rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"

tar -xJf "${ROOTFS_ARCHIVE}" -C "${ROOTFS_DIR}"

# 🔴 Minimal integrity validation
if [[ ! -x "${ROOTFS_DIR}/bin/bash" ]]; then
    vps_log "ERROR" "Invalid rootfs: /bin/bash missing" "$RED" >&2
    exit 1
fi

if [[ ! -d "${ROOTFS_DIR}/etc" || ! -d "${ROOTFS_DIR}/usr" ]]; then
    vps_log "ERROR" "Invalid rootfs: missing core directories" "$RED" >&2
    exit 1
fi

vps_log "INFO" "Rootfs extracted. Applying CPanel runtime defaults..." "$CYAN"

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
get-ssh() { /opt/cpanel-vps/scripts/start-ssh.sh; }
ssh() { get-ssh "$@"; }
alias ssh='get-ssh'
alias vps-ssh='get-ssh'
PS1='\[\033[0;32m\]root@\[\033[1;37m\]${VPS_HOSTNAME}\[\033[0;32m\]:\[\033[0;36m\]\w\[\033[0m\]# '
if [[ -z "\${CPANEL_VPS_BANNER_SHOWN:-}" ]]; then
    export CPANEL_VPS_BANNER_SHOWN=1
    vps_print_banner
    vps_help
fi
EOF

touch "${HOME}/.installed" "${ROOTFS_DIR}/.installed"

vps_log "INFO" "Rootfs ${ROOTFS_FILE} installed successfully." "$GREEN"
vps_log "INFO" "You can now use apt, bash, /etc, /bin, /usr and the rest of the userspace from the VPS shell." "$GREEN"
