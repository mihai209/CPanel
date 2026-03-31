#!/bin/bash

set -Eeuo pipefail

cd "${HOME:-/home/container}"

START_CMD="${STARTUP:-./run.sh}"
START_CMD="$(echo "$START_CMD" | sed -e 's/{{/${/g' -e 's/}}/}/g')"

exec /bin/bash -lc "$START_CMD"
