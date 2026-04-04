#!/bin/bash

set -Eeuo pipefail

source /opt/cpanel-vps/scripts/common.sh

export HOME="${HOME:-/home/container}"
mkdir -p "${HOME}" "${HOME}/logs"
cd "${HOME}"

SSH_CONFIG_FILE="${HOME}/ssh-conf.yml"
SSH_BIN="/opt/cpanel-vps/bin/cpanel-vps-ssh"

yaml_read() {
    local key="${1:-}"
    local file="${2:-}"
    awk -F': *' -v key="${key}" '$1 == key { sub(/^[^:]+:[[:space:]]*/, "", $0); print $0; exit }' "${file}" 2>/dev/null \
        | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

generate_password() {
    od -An -N18 -tx1 /dev/urandom | tr -d ' \n' | cut -c1-18
    printf '\n'
}

default_ssh_port() {
    vps_load_config
    if [[ ${#VPS_EXTRA_PORTS[@]} -gt 0 && -n "${VPS_EXTRA_PORTS[0]}" ]]; then
        printf '%s\n' "${VPS_EXTRA_PORTS[0]}"
        return 0
    fi
    printf '2222\n'
}

ensure_ssh_config() {
    if [[ -f "${SSH_CONFIG_FILE}" ]]; then
        return 0
    fi

    local default_port
    default_port="$(default_ssh_port)"
    local password
    password="$(generate_password)"

    cat > "${SSH_CONFIG_FILE}" <<EOF
SSH_PORT: ${default_port}
SSH_USERNAME: root
SSH_PASSWORD: ${password}
TIMEOUT: 5m
SSH_LOG: /logs/latest.txt
EOF
    chmod 600 "${SSH_CONFIG_FILE}"
}

ensure_ssh_config

if [[ ! -x "${SSH_BIN}" ]]; then
    vps_log "ERROR" "Missing SSH binary: ${SSH_BIN}" "${RED}" >&2
    exit 1
fi

SSH_USERNAME_VALUE="$(yaml_read SSH_USERNAME "${SSH_CONFIG_FILE}")"
SSH_PASSWORD_VALUE="$(yaml_read SSH_PASSWORD "${SSH_CONFIG_FILE}")"
SSH_PORT_VALUE="$(yaml_read SSH_PORT "${SSH_CONFIG_FILE}")"
SSH_LOG_VALUE="$(yaml_read SSH_LOG "${SSH_CONFIG_FILE}")"
SSH_TIMEOUT_VALUE="$(yaml_read TIMEOUT "${SSH_CONFIG_FILE}")"

if [[ -z "${SSH_USERNAME_VALUE}" || -z "${SSH_PASSWORD_VALUE}" || -z "${SSH_PORT_VALUE}" ]]; then
    vps_log "ERROR" "ssh-conf.yml must define SSH_PORT, SSH_USERNAME and SSH_PASSWORD." "${RED}" >&2
    exit 1
fi

ln -sfn "${HOME}/logs" /logs

"${SSH_BIN}" --config "${SSH_CONFIG_FILE}" --home "${HOME}" &
SSH_PID=$!

cleanup() {
    if kill -0 "${SSH_PID}" >/dev/null 2>&1; then
        kill "${SSH_PID}" >/dev/null 2>&1 || true
        wait "${SSH_PID}" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT INT TERM

sleep 1
if ! kill -0 "${SSH_PID}" >/dev/null 2>&1; then
    wait "${SSH_PID}"
    exit $?
fi

printf '%bRUNNING SSH DEVELOPED BY MIHAI209%b\n' "${CYAN}${BOLD}" "${NC}"
printf 'USERNAME : %s\n' "${SSH_USERNAME_VALUE}"
printf 'PASSWORD : %s\n' "${SSH_PASSWORD_VALUE}"
printf 'PORT     : %s\n' "${SSH_PORT_VALUE}"
printf 'TIMEOUT  : %s\n' "${SSH_TIMEOUT_VALUE:-5m}"
printf 'SSH LOG  : %s\n' "${SSH_LOG_VALUE:-/logs/latest.txt}"
printf '\n'
printf 'if you want to stop the ssh input q\n'

while IFS= read -r line; do
    if [[ "${line}" == "q" ]]; then
        break
    fi
done
