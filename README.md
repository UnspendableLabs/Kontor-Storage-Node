# Kontor Storage Node

[![Tests](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/tests.yml/badge.svg)](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/tests.yml)
[![Clippy](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/clippy.yml/badge.svg)](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/clippy.yml)
[![Format](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/fmt.yml/badge.svg)](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/fmt.yml)
[![Coverage](https://codecov.io/gh/UnspendableLabs/Kontor-Storage-Node/graph/badge.svg?token=Rwusewkjbh)](https://codecov.io/gh/UnspendableLabs/Kontor-Storage-Node)

A storage node CLI for the Kontor distributed storage network. This node communicates with the Kontor Portal API to participate in the storage network.

## Prerequisites

- Rust 1.70+ (edition 2021)
- A running Kontor Portal instance

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/Kontor-Storage-Node`.

## Usage

### Configuration

The node can be configured via command-line arguments or environment variables:

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--portal-url` | `PORTAL_API_URL` | `http://localhost:8080` | Portal API base URL |
| `--database-url` | `DATABASE_URL` | Local SQLite file under user data dir | Database connection string (SQLite/PostgreSQL/MySQL) |

### Database

- Default: SQLite file at `<data_dir>/Kontor-Storage-Node/storage.db` (auto-created).
- First launch on a new SQLite file triggers automatic migrations; for Postgres/MySQL run migrations manually.

#### Running migrations manually

```bash
cargo run -p migration -- up          # apply all
cargo run -p migration -- status      # check status
cargo run -p migration -- down -n 1   # rollback last
```

### Commands

#### Ping

Check connectivity with the Portal API:

```bash
./Kontor-Storage-Node ping
```

Or with a custom portal URL:

```bash
./Kontor-Storage-Node --portal-url https://portal.example.com/api ping
```

Using environment variable:

```bash
export PORTAL_API_URL=https://portal.example.com/api
./Kontor-Storage-Node ping
```

## Development

```bash
# Run in development mode
cargo run -- ping

# Run with custom portal URL
cargo run -- --portal-url http://localhost:3000 ping

# Run pointing to a specific database
cargo run -- --database-url sqlite://./local.db ping
```

## Architecture

See `docs/workflow.typ` for the complete system workflow diagram.

## License

TBD

