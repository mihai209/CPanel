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
ubuntu-24.04-amd64.tar.xz
ubuntu-24.04-arm64.tar.xz
debian-12-amd64.tar.xz
debian-12-arm64.tar.xz
```

## Build locally

```bash
docker build -t ghcr.io/mihai209/cpanel-vps:rootfs panel/images/misc/cpanel-vps-image
```

## Runtime model

- `entrypoint.sh` prepares `/home/container`
- `install.sh` downloads and extracts the requested rootfs
- `run.sh` launches an interactive `proot` shell inside that rootfs
- distro selection happens through egg variables:
  - `VPS_DISTRO`
  - `VPS_RELEASE`
  - `ROOTFS_BASE_URL`
  - `ROOTFS_TAG`
