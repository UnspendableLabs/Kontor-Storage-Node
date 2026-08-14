# Builder
# Pinned to the channel in rust-toolchain.toml, matching Kontor and the Horizon
# Portal so the shared kontor-crypto dependency set builds identically.
FROM rust:1.95-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src/ ./src/
# Needed to *build*: the dashboard's assets are embedded into the binary.
COPY static/ ./static/

RUN cargo build --release --locked

# Runtime
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The binary is the whole node: `static/` is compiled in, so nothing has to
# sit beside it and no working directory has to be the right one.
COPY --from=builder /build/target/release/kontor-storage-node /app/

RUN groupadd --system --gid 1001 kontor \
    && useradd --system --uid 1001 --gid 1001 --create-home --home-dir /home/kontor kontor \
    && mkdir -p /data \
    && chown -R kontor:kontor /app /data

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV KONTOR_APP_DIR=/data

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl --fail --silent --show-error http://localhost:8081/api/info || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run"]
