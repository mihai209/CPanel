# CPanel VPS Rootfs Builder

This directory is for the rootfs archives used by:

- `ghcr.io/mihai209/cpanel-vps:rootfs`
- `panel/images/misc/egg-c-panel-v-p-s.json`

The runtime image uses `proot`, then downloads one of these archives:

- `ubuntu-24.04-amd64.tar.xz`
- `ubuntu-24.04-arm64.tar.xz`
- `debian-12-amd64.tar.xz`
- `debian-12-arm64.tar.xz`

## What this gives you

Inside the VPS shell you get a real userspace tree:

- `/etc`
- `/bin`
- `/usr`
- `/var`
- `/root`

This is still not a full VM and not LXC. It is a `proot` userspace. That means:

- no custom kernel
- no systemd as PID 1
- no Docker inside by default
- apt, bash, nano, curl, file tree, package installs can work

## Publish flow

1. Build the rootfs archives with the GitHub Actions workflow.
2. Publish them to the `mihai209/cpanel-vps-rootfs` releases page.
3. Keep `ROOTFS_BASE_URL` and `ROOTFS_TAG` in the egg pointing there.

## Local build

Use `build-rootfs.sh` on a Debian/Ubuntu host with `debootstrap` installed.
