# Pinned toolchain for a cross-machine bit-reproducible coordinator build.
#
# The coordinator wasm's SHA-256 is load-bearing: anyone must be able to rebuild it from source and
# confirm deployed == source. Same-machine reproduction is proven by verify-build.sh; this image
# fixes the toolchain and source paths so the hash reproduces on any machine.
#
#   docker build -t ceremony-coordinator-build -f coordinator/Dockerfile .
#   docker run --rm -v "$PWD:/out" ceremony-coordinator-build \
#       bash -c "coordinator/build.sh && cp coordinator/coordinator.wasm coordinator/BUILD-HASH.txt /out/"
#
# Pins: dfx 0.31.0 (moc 1.1.0), mops CLI 2.8.0, mops packages core 1.0.0 + sha2 0.1.9 (mops.lock).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
      curl ca-certificates git bash coreutils libunwind8 && \
    rm -rf /var/lib/apt/lists/*

# Node (for mops) and dfx are pinned to exact versions.
ARG DFX_VERSION=0.31.0
ARG MOPS_VERSION=2.8.0
ARG NODE_MAJOR=20

RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get install -y nodejs && npm install -g ic-mops@${MOPS_VERSION}

RUN sh -c "DFX_VERSION=${DFX_VERSION} bash -c \"\$(curl -fsSL https://internetcomputer.org/install.sh)\"" || true
ENV PATH="/root/.local/share/dfx/bin:${PATH}"

WORKDIR /src
# Source is mounted or copied in; the ceremony coordinator + the in-repo BLS12-381 tower travel
# together. `mops install` restores the pinned packages from mops.lock before building.
COPY . /src
RUN cd /src && mops install || true

CMD ["bash", "coordinator/build.sh"]
