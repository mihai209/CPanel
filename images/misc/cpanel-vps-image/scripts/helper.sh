#!/bin/bash

cd "${HOME:-/home/container}"

START_CMD="${STARTUP:-./run.sh}"
START_CMD="$(echo "$START_CMD" | sed -e 's/{{/${/g' -e 's/}}/}/g')"

set +e +u
set +o pipefail

exec env -u SHELLOPTS HOME="${HOME:-/home/container}" STARTUP="${START_CMD}" /bin/bash -lc 'exec ${STARTUP}'
