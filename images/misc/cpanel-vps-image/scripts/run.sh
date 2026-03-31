#!/bin/bash

set -Eeuo pipefail

export HOME="${HOME:-/home/container}"
cd "$HOME"

exec /bin/bash --rcfile /opt/cpanel-vps/scripts/shellrc -i
