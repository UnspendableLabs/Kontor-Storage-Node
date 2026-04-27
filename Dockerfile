# Builder
FROM rust:1-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY migration/ ./migration/
COPY src/ ./src/
COPY static/ ./static/

RUN cargo build --release --locked

# Runtime
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/Kontor-Storage-Node /app/
COPY static/ /app/static/

RUN groupadd --system --gid 1001 kontor \
    && useradd --system --uid 1001 --gid 1001 --create-home --home-dir /home/kontor kontor \
    && mkdir -p /data \
    && chown -R kontor:kontor /app /data
USER kontor

ENV KONTOR_APP_DIR=/data

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl --fail --silent --show-error http://localhost:8081/api/info || exit 1

ENTRYPOINT ["/app/Kontor-Storage-Node"]
CMD ["run"]
