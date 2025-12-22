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
| `--portal-api-key` | `PORTAL_API_KEY` | _required_ | Portal API key used for Bearer authentication |
| `--portal-polling-interval-secs` | `PORTAL_POOLING_INTERVAL` | `30` | Interval in seconds between portal polling runs |
| `--database-url` | `DATABASE_URL` | Local SQLite file under user data dir | Database connection string (SQLite/PostgreSQL/MySQL) |
| `--storage-dir` | `STORAGE_DIR` | `<data_dir>/Kontor-Storage-Node/files` | Directory where downloaded files are stored |
| `--storage-capacity` | `STORAGE_CAPACITY` | _unlimited_ | Max storage for downloads (bytes, supports M/G/T suffix) |
| `--storage-max-files` | `STORAGE_MAX_FILES` | _unlimited_ | Max number of files to keep locally; when reached, new agreements are not fetched |
| `--storage-max-file-size` | `STORAGE_MAX_FILE_SIZE` | _unlimited_ | Max size for a single downloaded file (bytes, supports M/G/T suffix) |
| `--storage-method` | `STORAGE_METHOD` | `local` | Storage backend: `local` for local filesystem or `gcs` for Google Cloud Storage |
| `--storage-gcs-bucket-name` | `STORAGE_GCS_BUCKET_NAME` | _required if gcs_ | GCS bucket name (required when `STORAGE_METHOD=gcs`) |
| `--storage-gcs-service-account-json` | `STORAGE_GCS_SERVICE_ACCOUNT_JSON` | _required if gcs_ | Path to GCS service account JSON file (required when `STORAGE_METHOD=gcs`) |


You can also create a `.env.local` file in the project root; it is loaded automatically if present and provides the same environment variables as the table above. Example:

```
PORTAL_API_URL=https://portal.example.com/api
PORTAL_API_KEY=super-secret
PORTAL_POOLING_INTERVAL=45
DATABASE_URL=sqlite:///tmp/kontor.db
STORAGE_DIR=/tmp/kontor-files
STORAGE_CAPACITY=10GB
STORAGE_MAX_FILES=100
STORAGE_MAX_FILE_SIZE=500MB
STORAGE_METHOD=local
```

For Google Cloud Storage backend:

```
STORAGE_METHOD=gcs
STORAGE_GCS_BUCKET_NAME=my-kontor-bucket
STORAGE_GCS_SERVICE_ACCOUNT_JSON=/path/to/service-account.json
```

The `STORAGE_CAPACITY`, `STORAGE_MAX_FILES`, and `STORAGE_MAX_FILE_SIZE` limits apply in both `local` and `gcs` modes to respect quotas (for example, free tiers) even when files are stored remotely (uploaded to GCS).

When a `STORAGE_CAPACITY` is set, downloads are skipped if the next file would exceed the configured capacity, preserving disk space. When a `STORAGE_MAX_FILES` is set, the daemon stops fetching new agreements and downloading files once the stored file count reaches the limit.
When a `STORAGE_MAX_FILE_SIZE` is set, only agreements whose files are at or below that size are downloaded.

### Download and preparation pipeline

After an agreement file is downloaded into `storage_dir`, the node:

- prepares the file with `kontor_crypto::api::prepare_file`, discarding the `PreparedFile`;
- persists the resulting metadata directly on the `agreements` table (1:1 with each agreement);
- updates the aggregated ledger at `<storage_dir>/ledger.bin` via `FileLedger`, creating it when absent;
- marks the agreement as downloaded only after metadata and ledger persistence succeed.


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

