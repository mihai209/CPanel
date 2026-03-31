FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV TERM=xterm-256color
ENV HOME=/home/container

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
        proot \
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

RUN mkdir -p /home/container /opt/cpanel-vps/scripts

COPY scripts/common.sh /opt/cpanel-vps/scripts/common.sh
COPY scripts/entrypoint.sh /opt/cpanel-vps/scripts/entrypoint.sh
COPY scripts/helper.sh /opt/cpanel-vps/scripts/helper.sh
COPY scripts/install.sh /opt/cpanel-vps/scripts/install.sh
COPY scripts/run.sh /opt/cpanel-vps/scripts/run.sh

RUN chmod +x /opt/cpanel-vps/scripts/*.sh

WORKDIR /home/container
ENTRYPOINT ["/opt/cpanel-vps/scripts/entrypoint.sh"]
