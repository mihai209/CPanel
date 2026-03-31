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

vps_log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local color="${3:-$NC}"
    printf "%b[%s]%b %s\n" "$color" "$level" "$NC" "$message"
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
                port)
                    [[ -z "${VPS_MAIN_PORT}" && -n "$value" ]] && VPS_MAIN_PORT="$value"
                    ;;
                internalip)
                    [[ -n "$value" ]] && VPS_INTERNAL_IP="$value"
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
    distro="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-linux}")"
    pretty="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-Linux}")"
    printf "\033c"
    printf "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${CYAN}║${NC} ${WHITE}${BOLD}CPanel VPS Runtime${NC} ${DIM}(${pretty})${NC}\n"
    printf "${CYAN}║${NC} Hostname: ${GREEN}%s${NC}\n" "$VPS_HOSTNAME"
    printf "${CYAN}║${NC} Distro:   ${YELLOW}%s${NC}\n" "$distro"
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
  clear / cls        Clear the terminal
  exit               Stop the VPS container

Regular Debian/Ubuntu shell commands work normally:
  apt update
  apt install nano
  curl -I https://example.com
EOF
}

vps_status() {
    vps_load_config
    echo "Hostname : ${VPS_HOSTNAME}"
    echo "Kernel   : $(uname -srmo 2>/dev/null || uname -a)"
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
}
