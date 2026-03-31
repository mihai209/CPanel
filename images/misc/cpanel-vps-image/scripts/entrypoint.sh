#!/bin/bash

set -Eeuo pipefail

export HOME="${HOME:-/home/container}"
mkdir -p "$HOME"

for file in common.sh helper.sh install.sh run.sh; do
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
EOF
fi

cd "$HOME"

if [[ ! -f "$HOME/.installed" ]]; then
    /opt/cpanel-vps/scripts/install.sh
fi

exec /opt/cpanel-vps/scripts/helper.sh
