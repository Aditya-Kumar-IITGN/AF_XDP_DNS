FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    pkg-config \
    iproute2 \
    net-tools \
    tcpdump \
    iputils-ping \
    linux-headers-generic \
    libc6-dev-i386\
    ufw\
    m4\
    git\
    libpcap-dev\
    && rm -rf /var/lib/apt/lists/*

COPY . /src

WORKDIR /src

RUN ./configure
RUN make clean
RUN make

WORKDIR /src/lib/xdp-tools

RUN ./configure
RUN make
RUN make install

RUN ufw allow proto udp from any to any
RUN ufw allow out proto udp from any to any

RUN apt-get update && apt-get install -y --no-install-recommends \
    linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

# Auto-detect perf binary and link it
RUN PERF_PATH=$(find /usr/lib/linux-tools -name perf | head -n 1) && \
    echo "Using perf from: $PERF_PATH" && \
    ln -sf $PERF_PATH /usr/bin/perf

WORKDIR /src/main
RUN gcc -o server server.c
RUN gcc -o server_cached server_cached.c
# CMD ["./af_xdp_user", "-d", "eth0", "--filename", "./af_xdp_kern.o"]


EXPOSE 53