FROM --platform=$BUILDPLATFORM golang:1.24 AS ssh-builder

WORKDIR /src/ssh
ARG TARGETOS=linux
ARG TARGETARCH=amd64
COPY ssh /src/ssh
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/cpanel-vps-ssh ./cmd/cpanel-vps-ssh

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

RUN mkdir -p /home/container /opt/cpanel-vps/scripts /opt/cpanel-vps/bin

COPY --from=ssh-builder /out/cpanel-vps-ssh /opt/cpanel-vps/bin/cpanel-vps-ssh
COPY scripts/common.sh /opt/cpanel-vps/scripts/common.sh
COPY scripts/entrypoint.sh /opt/cpanel-vps/scripts/entrypoint.sh
COPY scripts/helper.sh /opt/cpanel-vps/scripts/helper.sh
COPY scripts/install.sh /opt/cpanel-vps/scripts/install.sh
COPY scripts/run.sh /opt/cpanel-vps/scripts/run.sh
COPY scripts/start-ssh.sh /opt/cpanel-vps/scripts/start-ssh.sh

RUN chmod +x /opt/cpanel-vps/scripts/*.sh /opt/cpanel-vps/bin/cpanel-vps-ssh

WORKDIR /home/container
ENTRYPOINT ["/opt/cpanel-vps/scripts/entrypoint.sh"]
