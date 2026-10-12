# syntax=docker/dockerfile:1
#
# Multi-stage build: compile the Rust CLI and the TypeScript API in their own
# images, then copy only the results into a slim runtime image that runs as
# the unprivileged `node` user.
#
# Behind a TLS-inspecting proxy, pass its CA bundle as an optional secret:
#   docker build --secret id=extra_ca,src=/path/to/ca-bundle.pem .

# ---- 1. Rust: build the lockwatch binary ----------------------------------
FROM rust:1-slim AS rust-build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/extra_ca; fi \
 && cargo build --release --locked -p lockwatch-cli \
 && strip target/release/lockwatch

# ---- 2. Node: compile the API and keep production dependencies ------------
# The full node image includes python3, make and g++, which better-sqlite3
# needs when no prebuilt binary matches.
FROM node:22 AS node-build
WORKDIR /app
COPY api/package.json api/package-lock.json ./
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi \
 && npm ci
COPY api/tsconfig.json api/tsconfig.build.json ./
COPY api/src ./src
RUN npm run build && npm prune --omit=dev

# ---- 3. Runtime --------------------------------------------------------------
FROM node:22-slim
ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    LOCKWATCH_BIN=/usr/local/bin/lockwatch \
    LOCKWATCH_CACHE_DIR=/cache \
    DB_PATH=/data/lockwatch.db
# CA certificates for the Rust binary's HTTPS client (rustls with the
# system trust store); the Rust image already has them.
COPY --from=rust-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust-build /src/target/release/lockwatch /usr/local/bin/lockwatch
WORKDIR /app
COPY --from=node-build /app/node_modules ./node_modules
COPY --from=node-build /app/dist ./dist
COPY api/package.json ./
RUN mkdir -p /data /cache && chown node:node /data /cache
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "dist/server.js"]
