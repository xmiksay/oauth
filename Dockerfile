# syntax=docker/dockerfile:1

# --- SPA ----------------------------------------------------------------------
FROM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- server -------------------------------------------------------------------
# Must match rust-toolchain.toml. That file is deliberately not copied: the
# image's toolchain is the pinned one, and the file would make rustup fetch the
# clippy/rustfmt components a release build never uses. The image's gcc is all
# aws-lc-sys (crypto provider) needs; it no longer requires cmake.
FROM rust:1.99.0-bookworm AS server
ENV CARGO_BUILD_JOBS=4
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin oauth \
    && cp target/release/oauth /usr/local/bin/oauth

# --- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 oauth \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin oauth
WORKDIR /app
COPY --from=server /usr/local/bin/oauth /usr/local/bin/oauth
COPY --from=web /src/web/dist /app/web/dist
ENV WEB_DIST_DIR=/app/web/dist \
    LISTEN_ADDR=0.0.0.0:8080 \
    METRICS_ADDR=0.0.0.0:9090 \
    LOG_FORMAT=json
USER 10001:10001
EXPOSE 8080 9090
ENTRYPOINT ["oauth"]
CMD ["serve"]
