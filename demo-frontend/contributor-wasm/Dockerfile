# Pinned toolchain for a cross-machine bit-reproducible contributor-client build.
#
# The contributor wasm is the code that samples and destroys a ceremony participant's secret, so
# the goal is that anyone can rebuild it and confirm the live page serves exactly this source.
# build.sh removes the path dependence; this image fixes the compiler, wasm-bindgen and wasm-opt
# versions so the remaining variables are held still on a machine that is not ours.
#
# That goal is not yet met, and this image is part of reaching it rather than evidence of it: the
# build still settles into one of two outputs differing in three bytes (constant ordering). A
# controlled environment like this one is the most likely place to pin that down, since the
# suspected cause is an ordering inside the compiler that depends on process memory layout.
#
#   docker build -t ceremony-contributor-build -f demo-frontend/contributor-wasm/Dockerfile .
#   docker run --rm -v "$PWD/out:/out" ceremony-contributor-build \
#       bash -c "demo-frontend/contributor-wasm/build.sh /out/pkg"
#
# Then compare /out/pkg against demo-frontend/contributor-wasm/PKG-HASHES.txt, and compare those
# against what the live page serves with scripts/verify-published-page.py.
#
# Pins: rustc 1.95.0 (rust-toolchain.toml), wasm-pack 0.13.1, binaryen (wasm-opt) 123.
FROM rust:1.95.0-bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
      curl ca-certificates git bash coreutils xz-utils && \
    rm -rf /var/lib/apt/lists/*

ARG WASM_PACK_VERSION=0.13.1
ARG BINARYEN_VERSION=123

RUN rustup target add wasm32-unknown-unknown

# Install wasm-pack at an exact version rather than via the "latest" installer script.
RUN cargo install wasm-pack --version ${WASM_PACK_VERSION} --locked

# wasm-pack will download a wasm-opt of its own choosing if it cannot find one; pin it explicitly,
# because the optimiser's version changes the output bytes and would otherwise silently float.
RUN curl -fsSL "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-x86_64-linux.tar.gz" \
      | tar -xz -C /opt && \
    ln -s /opt/binaryen-version_${BINARYEN_VERSION}/bin/wasm-opt /usr/local/bin/wasm-opt && \
    wasm-opt --version

WORKDIR /src
# The client travels with the crates it links: the `ceremony` contribution maths and circuit/common.
COPY . /src

CMD ["bash", "demo-frontend/contributor-wasm/build.sh"]
