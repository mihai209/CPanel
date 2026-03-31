#!/bin/bash

set -Eeuo pipefail

DISTRO="${1:-ubuntu}"
RELEASE="${2:-24.04}"
ARCH="${3:-amd64}"
OUT_DIR="${4:-$(pwd)/dist}"

resolve_suite() {
    local distro="$1"
    local release="$2"
    case "${distro}:${release}" in
        ubuntu:22.04) echo "jammy" ;;
        ubuntu:24.04) echo "noble" ;;
        debian:12) echo "bookworm" ;;
        debian:13) echo "trixie" ;;
        *)
            echo "Unsupported distro/release pair: ${distro} ${release}" >&2
            return 1
            ;;
    esac
}

case "${DISTRO}" in
    ubuntu|debian) ;;
    *)
        echo "Unsupported distro: ${DISTRO}" >&2
        exit 1
        ;;
esac

case "${ARCH}" in
    amd64|arm64) ;;
    *)
        echo "Unsupported arch: ${ARCH}" >&2
        exit 1
        ;;
esac

if ! command -v debootstrap >/dev/null 2>&1; then
    echo "debootstrap is required." >&2
    exit 1
fi

ROOTFS_NAME="${DISTRO}-${RELEASE}-${ARCH}"
SUITE="$(resolve_suite "${DISTRO}" "${RELEASE}")"
WORK_DIR="$(mktemp -d)"
ROOTFS_DIR="${WORK_DIR}/rootfs"

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUT_DIR}"

if [[ "${DISTRO}" == "ubuntu" ]]; then
    MIRROR="${UBUNTU_MIRROR:-http://archive.ubuntu.com/ubuntu}"
else
    MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"
fi

FOREIGN_ARGS=()
if [[ "$(dpkg --print-architecture 2>/dev/null || echo unknown)" != "${ARCH}" ]]; then
    FOREIGN_ARGS+=(--foreign)
fi

sudo debootstrap \
    --arch="${ARCH}" \
    --variant=minbase \
    "${FOREIGN_ARGS[@]}" \
    "${SUITE}" \
    "${ROOTFS_DIR}" \
    "${MIRROR}"

sudo mkdir -p "${ROOTFS_DIR}/etc/apt/apt.conf.d" "${ROOTFS_DIR}/root" "${ROOTFS_DIR}/tmp"
sudo chmod 1777 "${ROOTFS_DIR}/tmp"

cat <<'EOF' | sudo tee "${ROOTFS_DIR}/etc/apt/apt.conf.d/99cpanel-norecommend" >/dev/null
APT::Install-Recommends "0";
APT::Install-Suggests "0";
EOF

cat <<'EOF' | sudo tee "${ROOTFS_DIR}/root/.bashrc" >/dev/null
export TERM="${TERM:-xterm-256color}"
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
EOF

sudo rm -f "${ROOTFS_DIR}/etc/resolv.conf"
cat <<'EOF' | sudo tee "${ROOTFS_DIR}/etc/resolv.conf" >/dev/null
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

sudo tar -C "${ROOTFS_DIR}" -cJf "${OUT_DIR}/${ROOTFS_NAME}.tar.xz" .

echo "Created ${OUT_DIR}/${ROOTFS_NAME}.tar.xz"
