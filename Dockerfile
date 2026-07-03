# HiveGuard — Multi-stage Docker build
# Build: docker build -t hiveguard .
# Run:   docker run --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH -v /etc/hiveguard:/etc/hiveguard hiveguard

# ============================================================
# Stage 1: Builder
# ============================================================
FROM rust:1.87-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY hiveguard-core/Cargo.toml hiveguard-core/Cargo.toml
COPY hiveguard-ingest/Cargo.toml hiveguard-ingest/Cargo.toml
COPY hiveguard-net/Cargo.toml hiveguard-net/Cargo.toml
COPY hiveguard-enforce/Cargo.toml hiveguard-enforce/Cargo.toml
COPY hiveguard-daemon/Cargo.toml hiveguard-daemon/Cargo.toml
COPY hiveguard-bench/Cargo.toml hiveguard-bench/Cargo.toml

# Create dummy src files so cargo can resolve the workspace
RUN mkdir -p hiveguard-core/src && echo "pub fn _dummy() {}" > hiveguard-core/src/lib.rs && \
    mkdir -p hiveguard-ingest/src && echo "pub fn _dummy() {}" > hiveguard-ingest/src/lib.rs && \
    mkdir -p hiveguard-net/src && echo "pub fn _dummy() {}" > hiveguard-net/src/lib.rs && \
    mkdir -p hiveguard-enforce/src && echo "pub fn _dummy() {}" > hiveguard-enforce/src/lib.rs && \
    mkdir -p hiveguard-daemon/src && echo "fn main() {}" > hiveguard-daemon/src/main.rs && \
    mkdir -p hiveguard-bench/src && echo "fn main() {}" > hiveguard-bench/src/main.rs

# Pre-build dependencies (cached layer)
RUN cargo build --release -p hiveguard-daemon 2>/dev/null || true

# Copy actual source code
COPY hiveguard-core/ hiveguard-core/
COPY hiveguard-ingest/ hiveguard-ingest/
COPY hiveguard-net/ hiveguard-net/
COPY hiveguard-enforce/ hiveguard-enforce/
COPY hiveguard-daemon/ hiveguard-daemon/
COPY hiveguard-bench/ hiveguard-bench/

# Touch source files to invalidate cached compilation
RUN find . -name "*.rs" -exec touch {} +

# Build the release binary
RUN cargo build --release -p hiveguard-daemon

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nftables \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create system user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin hiveguard

# Create directories
RUN mkdir -p /etc/hiveguard /var/lib/hiveguard && \
    chown hiveguard:hiveguard /var/lib/hiveguard

# Copy binary from builder
COPY --from=builder /build/target/release/hiveguard-daemon /usr/local/bin/hiveguard

# Copy default config
COPY config.example.yaml /etc/hiveguard/config.yaml

# Volumes for config and state persistence
VOLUME ["/etc/hiveguard", "/var/lib/hiveguard"]

# Expose ports: gossip (QUIC) + REST API
EXPOSE 7946/udp 8443/tcp

USER hiveguard

ENTRYPOINT ["/usr/local/bin/hiveguard"]
CMD ["-c", "/etc/hiveguard/config.yaml"]
