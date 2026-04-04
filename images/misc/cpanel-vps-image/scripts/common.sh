#!/bin/bash

set -Eeuo pipefail

PURPLE='\033[0;35m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

VPS_HOSTNAME="${VPS_HOSTNAME:-}"
TIMEZONE="${TIMEZONE:-UTC}"
VPS_MAIN_PORT="${SERVER_PORT:-}"
VPS_INTERNAL_IP=""
VPS_EXTRA_PORTS=()
VPS_DISTRO="${VPS_DISTRO:-ubuntu}"
VPS_RELEASE="${VPS_RELEASE:-24.04}"
ROOTFS_BASE_URL="${ROOTFS_BASE_URL:-https://github.com/mihai209/cpanel-vps-rootfs/releases/download}"
ROOTFS_TAG="${ROOTFS_TAG:-latest}"
ROOTFS_FALLBACK_TAG="${ROOTFS_FALLBACK_TAG:-latest}"
ROOTFS_ARCH=""
ROOTFS_DIR="${HOME}/rootfs"
ROOTFS_ARCHIVE="${HOME}/rootfs.tar.xz"

vps_log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local color="${3:-$NC}"
    printf "%b[%s]%b %s\n" "$color" "$level" "$NC" "$message"
}

vps_detect_rootfs_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) ROOTFS_ARCH="amd64" ;;
        aarch64) ROOTFS_ARCH="arm64" ;;
        *)
            vps_log "ERROR" "Unsupported architecture for VPS rootfs: $arch" "$RED" >&2
            return 1
            ;;
    esac
}

vps_validate_distro() {
    case "${VPS_DISTRO}" in
        ubuntu|debian) return 0 ;;
        *)
            vps_log "ERROR" "Unsupported distro '${VPS_DISTRO}'. Only ubuntu and debian are allowed." "$RED" >&2
            return 1
            ;;
    esac
}

vps_rootfs_filename() {
    printf '%s-%s-%s.tar.xz' "${VPS_DISTRO}" "${VPS_RELEASE}" "${ROOTFS_ARCH}"
}

vps_rootfs_url_for_tag() {
    local tag="${1:-}"
    local base="${ROOTFS_BASE_URL%/}"
    local file
    file="$(vps_rootfs_filename)"
    if [[ -n "${tag}" ]]; then
        printf '%s/%s/%s' "${base}" "${tag}" "${file}"
    else
        printf '%s/%s' "${base}" "${file}"
    fi
}

vps_rootfs_url() {
    vps_rootfs_url_for_tag "${ROOTFS_TAG}"
}

vps_load_config() {
    local config_file="${HOME}/vps.config"
    if [[ -f "$config_file" ]]; then
        while IFS='=' read -r key value; do
            key="$(printf '%s' "$key" | tr -d '[:space:]')"
            value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            case "$key" in
                hostname)
                    [[ -z "${VPS_HOSTNAME}" && -n "$value" ]] && VPS_HOSTNAME="$value"
                    ;;
                timezone)
                    [[ "${TIMEZONE}" == "UTC" && -n "$value" ]] && TIMEZONE="$value"
                    ;;
                distro)
                    [[ "${VPS_DISTRO}" == "ubuntu" && -n "$value" ]] && VPS_DISTRO="$value"
                    ;;
                release)
                    [[ "${VPS_RELEASE}" == "24.04" && -n "$value" ]] && VPS_RELEASE="$value"
                    ;;
                port)
                    [[ -z "${VPS_MAIN_PORT}" && -n "$value" ]] && VPS_MAIN_PORT="$value"
                    ;;
                internalip)
                    [[ -n "$value" ]] && VPS_INTERNAL_IP="$value"
                    ;;
                port[2-9]|port1[0-9]|port20)
                    [[ -n "$value" ]] && VPS_EXTRA_PORTS+=("$value")
                    ;;
            esac
        done < "$config_file"
    fi

    if [[ -z "$VPS_HOSTNAME" ]]; then
        VPS_HOSTNAME="$(hostname 2>/dev/null || echo my-vps)"
    fi
    if [[ -z "$VPS_INTERNAL_IP" ]]; then
        VPS_INTERNAL_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i == "src") { print $(i+1); exit }}')"
    fi
}

vps_print_banner() {
    vps_load_config
    local distro pretty
    distro="${VPS_DISTRO}"
    pretty="${VPS_DISTRO} ${VPS_RELEASE}"
    printf "\033c"
    printf "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC} ${WHITE}${BOLD}CPanel VPS Runtime${NC} ${DIM}(${pretty})${NC}\n"
    printf "${CYAN}║${NC} Hostname: ${GREEN}%s${NC}\n" "$VPS_HOSTNAME"
    printf "${CYAN}║${NC} Distro:   ${YELLOW}%s${NC}\n" "$distro"
    printf "${CYAN}║${NC} Release:  ${YELLOW}%s${NC}\n" "${VPS_RELEASE}"
    printf "${CYAN}║${NC} IP:       ${BLUE}%s${NC}\n" "${VPS_INTERNAL_IP:-unknown}"
    printf "${CYAN}║${NC} Port:     ${PURPLE}%s${NC}\n" "${VPS_MAIN_PORT:-unassigned}"
    printf "${CYAN}║${NC} Timezone: ${WHITE}%s${NC}\n" "${TIMEZONE:-UTC}"
    printf "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

vps_help() {
    cat <<'EOF'
Available helper commands:
  help / vps-help    Show this help
  status / vps-status Show system summary
  ports / vps-ports  Show detected panel allocation info
  get-ssh           Start the custom VPS SSH listener from ssh-conf.yml
  clear / cls        Clear the terminal
  exit               Stop the VPS container

Regular Debian/Ubuntu shell commands work normally:
  apt update
  apt install nano
  curl -I https://example.com

Notes:
  - install.sh downloads the selected rootfs archive directly from ROOTFS_BASE_URL.
  - get-ssh reads /home/container/ssh-conf.yml.
  - For external SSH access, assign an extra allocation (PORT2 recommended).
EOF
}

vps_status() {
    vps_load_config
    vps_detect_rootfs_arch || true
    echo "Hostname : ${VPS_HOSTNAME}"
    echo "Kernel   : $(uname -srmo 2>/dev/null || uname -a)"
    echo "Distro   : ${VPS_DISTRO}"
    echo "Release  : ${VPS_RELEASE}"
    echo "Rootfs   : ${ROOTFS_DIR}"
    echo "Source   : $(vps_rootfs_url 2>/dev/null || echo unavailable)"
    echo "IP       : ${VPS_INTERNAL_IP:-unknown}"
    echo "Port     : ${VPS_MAIN_PORT:-unassigned}"
    echo "Uptime   : $(uptime -p 2>/dev/null || true)"
    echo "Memory   :"
    free -h 2>/dev/null || true
    echo "Disk     :"
    df -h "${HOME}" 2>/dev/null || df -h / 2>/dev/null || true
}

vps_ports() {
    vps_load_config
    if [[ -f "${HOME}/vps.config" ]]; then
        cat "${HOME}/vps.config"
    else
        echo "No vps.config found."
    fi
    if [[ ${#VPS_EXTRA_PORTS[@]} -gt 0 ]]; then
        echo
        echo "Extra Ports:"
        printf '  - %s\n' "${VPS_EXTRA_PORTS[@]}"
    fi
}
