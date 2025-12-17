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
```

## Architecture

See `docs/workflow.typ` for the complete system workflow diagram.

## License

TBD

