# Kontor Storage Node

[![CI](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/ci.yml/badge.svg)](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/UnspendableLabs/Kontor-Storage-Node/graph/badge.svg?token=Rwusewkjbh)](https://codecov.io/gh/UnspendableLabs/Kontor-Storage-Node)

A storage node CLI for the Kontor distributed storage network. This node communicates with the Kontor Portal API to participate in the storage network.

## Prerequisites

- Rust stable (managed via [rust-toolchain.toml](rust-toolchain.toml))
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
| `--portal-polling-interval-secs` | `PORTAL_POLLING_INTERVAL` | `30` | Interval in seconds between portal polling runs (env: `PORTAL_POOLING_INTERVAL` is also accepted for backward compatibility but deprecated.) |
| `--database-url` | `DATABASE_URL` | Local SQLite file under user data dir | Database connection string (SQLite/PostgreSQL/MySQL) |
| `--storage-dir` | `STORAGE_DIR` | `<data_dir>/Kontor-Storage-Node/files` | Directory where downloaded files are stored |
| `--storage-capacity` | `STORAGE_CAPACITY` | _unlimited_ | Max storage for downloads (bytes, supports M/G/T suffix) |
| `--storage-max-files` | `STORAGE_MAX_FILES` | _unlimited_ | Max number of files to keep locally; when reached, new agreements are not fetched |
| `--storage-max-file-size` | `STORAGE_MAX_FILE_SIZE` | _unlimited_ | Max size for a single downloaded file (bytes, supports M/G/T suffix) |
| `--storage-method` | `STORAGE_METHOD` | `local` | Storage backend: `local` for local filesystem or `gcs` for Google Cloud Storage |
| `--storage-gcs-bucket-name` | `STORAGE_GCS_BUCKET_NAME` | _required if gcs_ | GCS bucket name (required when `STORAGE_METHOD=gcs`) |
| `--storage-gcs-service-account-json` | `STORAGE_GCS_SERVICE_ACCOUNT_JSON` | _required if gcs_ | Path to GCS service account JSON file, or inline JSON (Horizon Portal: `[n]` newline escapes; required when `STORAGE_METHOD=gcs`) |
| `--server-address` | `SERVER_ADDRESS` | `0.0.0.0:8081` | Address the public HTTP server binds to |
| `--public-url` | `PUBLIC_URL` | `http://localhost:8081` | Public URL where this node is reachable for file downloads |
| `--bls-key-path` | `BLS_KEY_PATH` | `<data_dir>/Kontor-Storage-Node/bls_key.enc` | Path to the encrypted BLS key file. For non-interactive mode, also set `BLS_PASSWORD`. |
| `--kontor-contract-address` | `KONTOR_CONTRACT_ADDRESS` | `filestorage_0_0` | Kontor address of the filestorage contract. **Must match the Portal's own `KONTOR_CONTRACT_ADDRESS`**: the address is part of every signed Kontor op, so a mismatch makes the Portal reject every join and proof signature. |


You can also create a `.env.local` file in the project root; it is loaded automatically if present and provides the same environment variables as the table above. Example:

```
PORTAL_API_URL=https://portal.example.com/api
PORTAL_POLLING_INTERVAL=45
DATABASE_URL=sqlite:///tmp/kontor.db
STORAGE_DIR=/tmp/kontor-files
STORAGE_CAPACITY=10GB
STORAGE_MAX_FILES=100
STORAGE_MAX_FILE_SIZE=500MB
STORAGE_METHOD=local
SERVER_ADDRESS=0.0.0.0:8081
PUBLIC_URL=http://localhost:8081
```

For Google Cloud Storage backend:

```
STORAGE_METHOD=gcs
STORAGE_GCS_BUCKET_NAME=my-kontor-bucket
STORAGE_GCS_SERVICE_ACCOUNT_JSON=/path/to/service-account.json
# or inline JSON (e.g. from a secret manager), with `[n]` for newlines in `private_key`:
# STORAGE_GCS_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}'
```

The `STORAGE_CAPACITY`, `STORAGE_MAX_FILES`, and `STORAGE_MAX_FILE_SIZE` limits apply in both `local` and `gcs` modes to respect quotas (for example, free tiers) even when files are stored remotely (uploaded to GCS).

When a `STORAGE_CAPACITY` is set, downloads are skipped if the next file would exceed the configured capacity, preserving disk space. When a `STORAGE_MAX_FILES` is set, the daemon stops fetching new agreements and downloading files once the stored file count reaches the limit.
When a `STORAGE_MAX_FILE_SIZE` is set, only agreements whose files are at or below that size are downloaded.

### Download and preparation pipeline

After an agreement file is downloaded into `storage_dir`, the node:

- prepares the file with `kontor_crypto::api::prepare_file(bytes, filename, &[])`, discarding the `PreparedFile`. The empty nonce is not arbitrary: the Portal publishes every file descriptor with `nonce: []`, and the nonce enters the `file_id` hash;
- persists the resulting metadata directly on the `agreements` table (1:1 with each agreement);
- marks the agreement as downloaded once metadata persistence succeeds.

### The aggregated ledger

`<storage_dir>/ledger.bin` is a **derived artifact**, rebuilt from the database
once per sync cycle (just before proofs are computed) rather than appended to
during downloads.

Since kontor-crypto 0.3.0 the aggregated ledger is append-only and the
filestorage contract owns the slot counter: each file gets a stable
`ledger_index` at `create-agreement` time. That slot is a public input of the
Proof-of-Retrievability SNARK — the prover resolves it from its local
`FileLedger`, the contract from its own registry — so the node places each file
at its **absolute on-chain slot** (`FileLedger::add_files` with explicit
indices), not at its local insertion order.

The `ledger_index` comes from the Portal's agreements API and is only known once
the creating Bitcoin transaction has been confirmed and reconciled against
Kontor. Agreements still awaiting it are downloaded and served normally but left
out of the ledger, and are logged as unprovable until the slot arrives.

**Known limitation.** `FileLedger` refuses a set of slots whose highest index
exceeds the file count by more than `MAX_LEDGER_INDEX_SPARSITY_GAP` (1024 in
kontor-crypto 0.3.0). A node holding only a subset of the network's files at
their absolute on-chain slots therefore stops being able to rebuild the ledger
once the contract's slot counter runs more than ~1024 ahead of what the node
stores. The rebuild failure is logged and the sync cycle continues — downloads,
agreement sync and file serving are unaffected — but proofs are skipped until
the constraint is lifted upstream.


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

### HTTP Server

When the daemon runs (`./Kontor-Storage-Node run`), it exposes a public HTTP server on `0.0.0.0:8081` by default (override via `--server-address` or `SERVER_ADDRESS`) for serving downloaded files and a dashboard.

Endpoints:

| Path | Description |
|------|-------------|
| `GET /` | HTML dashboard listing stored files |
| `GET /api/info` | JSON: `{ "node_id": "..." }` |
| `GET /files?offset=&limit=` | JSON: paginated list of stored files |
| `GET /files/:file_id` | Download (local backend) or 307 redirect to a GCS signed URL |
| `GET /static/*` | Static assets (logo, dashboard CSS/JS) |

CORS is permissive (`Access-Control-Allow-Origin: *`). All routes are public — see [`src/server/routes.rs`](src/server/routes.rs) for the security model. See [`apiary.apib`](apiary.apib) for the full API specification.

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

To be defined. See `LICENSE` (file pending) for terms.

