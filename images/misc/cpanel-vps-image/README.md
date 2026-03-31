# CPanel VPS Image

Custom VPS-style container image for CPanel.

It is intentionally simpler than nested LXC eggs:
- no `images.linuxcontainers.org`
- no nested container runtime
- no privileged LXC dependency
- direct Debian/Ubuntu runtime shell inside the server container

## Tags

- `ghcr.io/mihai209/cpanel-vps:ubuntu`
- `ghcr.io/mihai209/cpanel-vps:debian`

## Build locally

```bash
docker build -t ghcr.io/mihai209/cpanel-vps:ubuntu --build-arg BASE_IMAGE=ubuntu:24.04 panel/images/misc/cpanel-vps-image
docker build -t ghcr.io/mihai209/cpanel-vps:debian --build-arg BASE_IMAGE=debian:12-slim panel/images/misc/cpanel-vps-image
```

## Behavior

- `entrypoint.sh` ensures standard helper scripts exist in `/home/container`
- `install.sh` performs first-boot bootstrap only
- `run.sh` launches an interactive bash shell with a custom rcfile
- `vps.config` is used for prompt and display metadata when present
