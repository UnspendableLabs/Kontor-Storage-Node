# Builder
FROM rust:1-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY migration/ ./migration/
COPY src/ ./src/

RUN cargo build --release

# Runtime
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/Kontor-Storage-Node /app/
COPY static/ /app/static/

ENV KONTOR_APP_DIR=/data

EXPOSE 8081

ENTRYPOINT ["/app/Kontor-Storage-Node"]
CMD ["run"]
