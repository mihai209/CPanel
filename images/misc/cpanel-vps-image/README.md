# CPanel VPS Image

Custom VPS-style image for CPanel using:
- `proot`
- downloaded Debian/Ubuntu rootfs archives
- a full userspace inside `/home/container/rootfs`

This preserves the expected filesystem tree (`/etc`, `/bin`, `/usr`, `/var`, ...), but avoids nested LXC/LXD.

## GHCR tag

- `ghcr.io/mihai209/cpanel-vps:rootfs`

## Expected rootfs archive layout

The image downloads rootfs archives from a URL you control, for example GitHub Releases:

```text
https://github.com/mihai209/cpanel-vps-rootfs/releases/download/latest/
```

Expected filenames:

```text
ubuntu-22.04-amd64.tar.xz
ubuntu-24.04-amd64.tar.xz
ubuntu-24.04-arm64.tar.xz
debian-12-amd64.tar.xz
debian-12-arm64.tar.xz
debian-13-amd64.tar.xz
```

## Build locally

```bash
docker build -t ghcr.io/mihai209/cpanel-vps:rootfs panel/images/misc/cpanel-vps-image
```

## Runtime model

- `entrypoint.sh` prepares `/home/container`
- `install.sh` downloads and extracts the requested rootfs directly from `ROOTFS_BASE_URL`
- `run.sh` launches an interactive `proot` shell inside that rootfs
- `get-ssh` starts the bundled Go SSH server from inside the VPS shell
- distro selection happens through egg variables:
  - `VPS_DISTRO`
  - `VPS_RELEASE`
  - `ROOTFS_BASE_URL`
  - `ROOTFS_TAG`
  - `ROOTFS_FALLBACK_TAG`
- quick presets currently exposed in the egg UI:
  - `Ubuntu 22.04`
  - `Ubuntu 24.04`
  - `Debian 12`
  - `Debian 13`

## SSH runtime

The runtime creates `/home/container/ssh-conf.yml` automatically on first boot:

```yaml
SSH_PORT: 2222
SSH_USERNAME: root
SSH_PASSWORD: generated-on-first-boot
TIMEOUT: 5m
SSH_LOG: /logs/latest.txt
```

Notes:

- `PORT2` is the recommended external allocation for `SSH_PORT`.
- If `TIMEOUT` is `0`, sessions never auto-close.
- `/logs/latest.txt` is backed by `/home/container/logs/latest.txt`.
- Start the listener from the VPS shell with:

```bash
get-ssh
```

## Validation

There is also a smoke-test workflow:

- `.github/workflows/vps-image-smoke.yml`

It builds the runtime image, prepares a temporary Ubuntu rootfs archive, and verifies that `proot` can enter a filesystem exposing `/etc`, `/bin`, and `/usr`.
