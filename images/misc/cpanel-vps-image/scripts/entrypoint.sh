#!/bin/bash

set -Eeuo pipefail

export HOME="${HOME:-/home/container}"
mkdir -p "$HOME" "$HOME/logs"
ln -sfn "$HOME/logs" /logs

for file in common.sh helper.sh install.sh run.sh start-ssh.sh; do
    if [[ ! -f "$HOME/$file" ]]; then
        cp "/opt/cpanel-vps/scripts/$file" "$HOME/$file"
    fi
    chmod +x "$HOME/$file"
done

if [[ ! -f "$HOME/vps.config" ]]; then
    cat > "$HOME/vps.config" <<EOF
internalip=${SERVER_IP:-127.0.0.1}
port=${SERVER_PORT:-}
hostname=${VPS_HOSTNAME:-my-vps}
timezone=${TIMEZONE:-UTC}
distro=${VPS_DISTRO:-ubuntu}
release=${VPS_RELEASE:-24.04}
EOF
fi

if [[ ! -f "$HOME/ssh-conf.yml" ]]; then
    ssh_port="${PORT2:-2222}"
    if [[ -z "${ssh_port}" ]]; then
        ssh_port="2222"
    fi
    ssh_password="$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n' | cut -c1-18)"
    cat > "$HOME/ssh-conf.yml" <<EOF
SSH_PORT: ${ssh_port}
SSH_USERNAME: root
SSH_PASSWORD: ${ssh_password}
TIMEOUT: 5m
SSH_LOG: /logs/latest.txt
EOF
    chmod 600 "$HOME/ssh-conf.yml"
fi

cd "$HOME"

if [[ ! -f "$HOME/.installed" ]]; then
    /opt/cpanel-vps/scripts/install.sh
fi

exec /opt/cpanel-vps/scripts/helper.sh
