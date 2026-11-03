# syntax=docker/dockerfile:1.7

FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY frontend ./frontend
COPY widget-dist ./widget-dist
COPY widget-source/package.json widget-source/bun.lock widget-source/_build_only.mjs ./widget-source/
# Widget-node_modules is not present here, so build.rs embeds the tracked,
# CI-tested widget-dist artifacts instead of rebuilding them.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --locked -p cap-server \
    && install -Dm755 target/release/cap-server /out/cap-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 cap \
    && useradd --system --uid 10001 --gid cap --home-dir /data --shell /usr/sbin/nologin cap \
    && install -d -o cap -g cap -m 0700 /data

COPY --from=build /out/cap-server /usr/local/bin/cap-server

ENV CAPPRO_DIR=/data \
    SERVER_HOSTNAME=0.0.0.0 \
    SERVER_PORT=3000

USER cap
VOLUME ["/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:3000/health/live || exit 1

ENTRYPOINT ["/usr/local/bin/cap-server"]
