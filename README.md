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
| `--admin-password` | `ADMIN_PASSWORD` | _unset (UI disabled)_ | Password for the operator UI at `/admin`. At least 16 characters when set; leave unset to disable the UI entirely. See [Operator UI](#operator-ui). |
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
| `GET /admin` | Operator UI (password-gated, see below) |
| `POST /api/admin/login` | Exchange `ADMIN_PASSWORD` for an 8-hour session token |
| `GET /api/admin/status` | JSON: row counts and storage summary (session required) |
| `POST /api/admin/reset-database` | Wipe the node's database, optionally restarting the node (session required) |

CORS is permissive (`Access-Control-Allow-Origin: *`) on the serving routes, which are all public — see [`src/server/routes.rs`](src/server/routes.rs) for the security model. The `/admin` routes are deliberately outside that CORS layer and carry their own password gate. See [`apiary.apib`](apiary.apib) for the full API specification.

### Operator UI

Setting `ADMIN_PASSWORD` (at least 16 characters) enables a single-page operator UI at `/admin`. Leaving it unset — the default — disables it: the page still renders, but login answers `503 ADMIN_UI_DISABLED`. It is the counterpart of the Horizon Portal's own `/admin` page and is protected the same way:

- the password is exchanged at `POST /api/admin/login` for a session token that expires after 8 hours and is held in `sessionStorage`, never a cookie;
- the token is signed with a key generated at startup and never persisted, so restarting the node ends every session;
- failed logins are throttled per peer IP (10 per 15 minutes) with a fixed 250 ms delay on each rejection, and the password is compared in constant time;
- `X-Forwarded-For` is not trusted, so behind a reverse proxy every client shares one throttle bucket (which fails closed, not open).

The UI shows what the node holds and offers one action: **reset the database**. It deletes every row of `agreements` and `challenges` — both are chain-derived, so after a Kontor signet reset they refer to a chain that no longer exists — and the daemon then re-fetches agreements from the Portal from scratch. It requires typing `RESET` to confirm.

Stored file blobs are kept by default and become orphans; ticking *also delete the stored file blobs* removes them too (local files, or objects in the node's GCS bucket). Only blobs named by the rows being deleted are removed, so the BLS key, the daemon lock and anything else in the storage directory always survive.

#### Restarting after a reset

The wipe does not re-register the node, and cannot: the `signer_id`, the JWT and the announced public URL are read once during onboarding and then held for the life of the process, and a signet reset invalidates all three. The full recovery is therefore:

1. re-register the node's BLS key on the Portal — the node never issues `RegisterBlsKey` itself, it only waits for the resulting `signer_id` to appear;
2. reset the database with **restart the node after the wipe** ticked;
3. the node exits with code `75` and the supervisor starts it again, which re-runs onboarding, re-announces the URL and reconciles against the new chain.

Restarting also settles any download still in flight, which would otherwise write a file back after the wipe.

The exit code is deliberately non-zero: Railway's default policy and Docker Compose's `restart: on-failure` only bring back a container that failed, so a clean `0` would leave the node stopped.

The restart is offered only when `BLS_PASSWORD` is set. Without it, onboarding prompts for the key password on a terminal a restarted container does not have, so the node would go down and stay down — the checkbox is disabled and the API answers `400 RESTART_UNAVAILABLE`. Reset without it and restart the node yourself.

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

