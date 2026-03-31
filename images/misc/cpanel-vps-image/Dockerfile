FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TERM=xterm-256color
ENV HOME=/home/container
ENV PROOT_VERSION=5.4.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        file \
        grep \
        iproute2 \
        iputils-ping \
        jq \
        less \
        nano \
        net-tools \
        procps \
        psmisc \
        sed \
        sudo \
        tar \
        tzdata \
        unzip \
        vim-tiny \
        wget \
        xz-utils \
        zip \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH="$(uname -m)" \
    && case "$ARCH" in \
        x86_64) PROOT_ARCH="amd64" ;; \
        aarch64) PROOT_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/proot-me/proot-static-build/releases/download/v${PROOT_VERSION}/proot-v${PROOT_VERSION}-${PROOT_ARCH}.tar.gz" -o /tmp/proot.tar.gz \
    && tar -xzf /tmp/proot.tar.gz -C /tmp \
    && find /tmp -type f -name proot -exec cp {} /usr/local/bin/proot \; \
    && chmod 755 /usr/local/bin/proot \
    && rm -rf /tmp/proot.tar.gz /tmp/proot*

RUN mkdir -p /home/container /opt/cpanel-vps/scripts

COPY scripts/common.sh /opt/cpanel-vps/scripts/common.sh
COPY scripts/entrypoint.sh /opt/cpanel-vps/scripts/entrypoint.sh
COPY scripts/helper.sh /opt/cpanel-vps/scripts/helper.sh
COPY scripts/install.sh /opt/cpanel-vps/scripts/install.sh
COPY scripts/run.sh /opt/cpanel-vps/scripts/run.sh

RUN chmod +x /opt/cpanel-vps/scripts/*.sh

WORKDIR /home/container
ENTRYPOINT ["/opt/cpanel-vps/scripts/entrypoint.sh"]
