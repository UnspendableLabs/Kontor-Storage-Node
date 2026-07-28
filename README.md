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
| `--bls-key-path` | `BLS_KEY_PATH` | `<data_dir>/Kontor-Storage-Node/bls_key.enc` | Path to the encrypted BLS key file. For non-interactive mode, also set `BLS_PASSWORD`. Ignored entirely when `KONTOR_STORAGE_MNEMONIC` is set. |
| _(env only)_ | `KONTOR_STORAGE_MNEMONIC` | _unset_ | Horizon Wallet seed phrase. Setting it puts the node in [mnemonic mode](#mnemonic-mode): it derives its own keys and registers itself, and `BLS_ENCRYPTED_BLOB` / `BLS_PASSWORD` are ignored. |
| _(env only)_ | `KONTOR_STORAGE_ACCOUNT_INDEX` | `0` | Which wallet account to derive. Must match the account the node is registered under — see [mnemonic mode](#mnemonic-mode). |
| _(env only)_ | `KONTOR_STORAGE_NETWORK` | `signet` | `mainnet`, `testnet`, or `signet`. Selects the coin type in both derivation paths, so it changes every derived key. |
| _(env only)_ | `KONTOR_STORAGE_REGISTER_NEW_ACCOUNT` | `0` | Set to `1` to register this account as a **new** node even though other accounts of the same mnemonic already have one — see [running several nodes from one mnemonic](#running-several-nodes-from-one-mnemonic). |
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

### Mnemonic mode

Set `KONTOR_STORAGE_MNEMONIC` and the node needs nothing else to reach a running
state — no Horizon Wallet, no browser, no key file:

```
KONTOR_STORAGE_MNEMONIC="word1 word2 ... word12"
KONTOR_STORAGE_ACCOUNT_INDEX=2
KONTOR_STORAGE_NETWORK=signet
```

Without it, bringing a node up takes the wallet twice: once to export the BLS key
as `BLS_ENCRYPTED_BLOB`, and again from a browser to sign the Schnorr half of the
proof of possession that registration needs, because the Taproot key never leaves
the extension. With the seed phrase the node derives both keys itself, so it can
sign a complete registration — which also means it re-registers itself unattended
after the Portal's database is reset, instead of waiting for someone to open
`/admin`.

Derivation matches Horizon Wallet exactly (BIP-39 with an empty passphrase, then
`m/12381/{coin}/{account}/0` for the BLS key via EIP-2333 and
`m/86'/{coin}'/{account}'/0/0` for the Taproot key), so a mnemonic node and a
wallet-exported one with the same account are the same node.

On startup it prints the identity it derived:

```
✓ Identity derived from KONTOR_STORAGE_MNEMONIC (signet, account 2)
  BLS public key:  9251e095…
  Taproot xpub:    tpubDF…
  Taproot address: tb1p…q2x   <- whitelist this on the Portal
  Node id:         node-8f3a…
```

The Taproot address is the one thing a Portal admin still has to act on: node
registration is gated on a whitelist of addresses. Until it is whitelisted the
Portal answers `403 ADDRESS_NOT_WHITELISTED` and the node serves `/admin` — where
the address is also shown — while re-offering the same registration every 30
seconds. Nobody else can offer it: the Taproot key that signs it never leaves the
process. So whitelisting the address is the whole of the operator's work; the
node comes up on its own within the next tick, no restart needed.

> [!IMPORTANT]
> `KONTOR_STORAGE_MNEMONIC` is the seed phrase itself, not a key derived from it,
> so it reaches far beyond this node: the same phrase controls every account of
> that wallet, on mainnet as well as signet. Anything that can read the node's
> environment — `docker inspect`, a platform dashboard, `/proc/<pid>/environ`, a
> core dump — holds the whole wallet, not just this node's identity.
>
> Use a wallet dedicated to running nodes, and keep the funds elsewhere. The node
> itself never logs the phrase, never writes it to disk, and never serves it on
> `/admin`, but it cannot do anything about where the variable is stored.

#### Running several nodes from one mnemonic

One mnemonic backs as many nodes as it has accounts — one node per
`KONTOR_STORAGE_ACCOUNT_INDEX`. Because of that, "another account of this
mnemonic is registered" is ambiguous: it is what a mistyped account index looks
like, and it is also what a second node legitimately looks like. The node cannot
tell the two apart, and the first is destructive, so it refuses by default and
asks:

```
KONTOR_STORAGE_REGISTER_NEW_ACCOUNT=1
```

Set that alongside the account index for a genuinely new node, and it registers
next to the existing ones, listing them as it goes so a list that does not match
the nodes you think you run is still visible. Leave it unset everywhere else —
it is the only thing standing between a typo and a second identity.

#### Migrating a running node

Add `KONTOR_STORAGE_MNEMONIC` and `KONTOR_STORAGE_ACCOUNT_INDEX`, remove
`BLS_ENCRYPTED_BLOB` and `BLS_PASSWORD`, and restart. The mnemonic is checked
before the key file, so the `bls_key.enc` left over from the export is ignored
rather than prompting for a password the container cannot supply — leave it or
delete it, it makes no difference.

The account index has to be the one the node is already registered under. If it
is not, the node **refuses to start** rather than registering a second identity
and stranding the first one's agreements:

```
No node is registered for KONTOR_STORAGE_ACCOUNT_INDEX = 1 (signet).
  derived BLS key: 84a1c0…
  derived address: tb1p…7k2q

  This mnemonic does have registered nodes, on other accounts (accounts 0-10 checked):
    account 2 (signet) -> node-8f3a… (tb1p…q2x)
    account 3 (signet) -> node-1b7c… (tb1p…m4d)

  If this node should be one of those, set KONTOR_STORAGE_ACCOUNT_INDEX to its
  account. Registering account 1 instead would create a second node and leave
  that one's agreements behind.

  If this really is a new node alongside them, set
  KONTOR_STORAGE_REGISTER_NEW_ACCOUNT=1 to say so and it will register account 1
  on the next start.
```

It finds those by deriving the neighbouring accounts and asking the Portal about
each, which also catches a wrong `KONTOR_STORAGE_NETWORK` — the wrong coin type
produces a key the Portal has never seen, exactly like a wrong account.

The scan stops at account 10, which is why every message says so. Past it there
is nothing to find and nothing to refuse, so a node whose real account is 11 or
beyond registers a second identity without a word — set the account index from
what the wallet shows rather than relying on being caught.

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

**Known limitation — this node stops proving on a network of any size.**
`FileLedger::add_files` rebuilds the aggregated Merkle tree eagerly and refuses
a set of slots whose highest index implies more leaves than the file count plus
`MAX_LEDGER_INDEX_SPARSITY_GAP` (1024 in kontor-crypto 0.3.0). A node holding
only a subset of the network's files at their absolute on-chain slots therefore
stops being able to build a `FileLedger` at all once the contract's slot counter
runs more than ~1024 ahead of what the node stores.

Nothing about a proof needs that aggregated tree: this node only ever submits
single-file proofs, for which the verifier skips the ledger-root check entirely
(`aggregated_tree_depth` must be 0) and uses the file's own Merkle root. Only
the per-file slot is a public input. The wall is imposed by ledger
*construction*, not by the statement being proven, so it needs an upstream fix —
placing a file at an arbitrary slot without materializing every leaf below it.

Until then the failure is contained but total: the rebuild error is logged and
the sync cycle continues — downloads, agreement sync and file serving are
unaffected — but every proof is skipped. Because a log line is easy to miss, the
operator UI answers this directly: `GET /api/admin/status` returns a `ledger`
block with `rebuild_blocked`, which applies the same predicate to the node's own
rows and so goes true *before* the next rebuild fails.


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
| `GET /api/admin/status` | JSON: row counts, storage summary and registration state (session required) |
| `POST /api/admin/reset-database` | Wipe the node's database, optionally restarting the node (session required) |
| `POST /api/admin/register-node` | Register the node's BLS key on the Portal (session required) |

CORS is permissive (`Access-Control-Allow-Origin: *`) on the serving routes, which are all public — see [`src/server/routes.rs`](src/server/routes.rs) for the security model. The `/admin` routes are deliberately outside that CORS layer and carry their own password gate. See [`apiary.apib`](apiary.apib) for the full API specification.

### Operator UI

Setting `ADMIN_PASSWORD` (at least 16 characters) enables a single-page operator UI at `/admin`. Leaving it unset — the default — disables it: the page still renders, but login answers `503 ADMIN_UI_DISABLED`. It is the counterpart of the Horizon Portal's own `/admin` page and is protected the same way:

- the password is exchanged at `POST /api/admin/login` for a session token that expires after 8 hours and is held in `sessionStorage`, never a cookie;
- the token is signed with a key generated at startup and never persisted, so restarting the node ends every session;
- failed logins are throttled per peer IP (10 per 15 minutes) with a fixed 250 ms delay on each rejection, and the password is compared in constant time;
- `X-Forwarded-For` is not trusted, so behind a reverse proxy every client shares one throttle bucket (which fails closed, not open).

The UI shows what the node holds and offers two actions: **register the node on the Portal** and **reset the database**.

#### Reset the database

Deletes every row of `agreements` and `challenges` — both are chain-derived, so after a Kontor signet reset they refer to a chain that no longer exists — and the daemon then re-fetches agreements from the Portal from scratch. It requires typing `RESET` to confirm.

Stored file blobs are kept by default and become orphans; ticking *also delete the stored file blobs* removes them too (local files, or objects in the node's GCS bucket). Only blobs named by the rows being deleted are removed, so the BLS key, the daemon lock and anything else in the storage directory always survive.

#### Register the node on the Portal

A Portal database reset drops every `nodes` row, so the node's next `GET /api/nodes/lookup` answers `404` and it has no `signer_id` to sign with. Rather than exiting — which would take `/admin` down with it — the node starts the server with the daemon switched off and offers the registration card, so the one page that can fix the problem is the one page still running.

`POST /api/nodes/register` wants five fields, and the node produces three of them itself:

| Field | Source |
|-------|--------|
| `xpubkey` | Horizon Wallet (`getBLSPoP`) |
| `schnorr_sig` | Horizon Wallet — BIP340 over `sha256("KONTOR_XONLY_TO_BLS_V1" ‖ bls_pubkey)`, so it needs the Taproot secret key |
| `bls_pubkey` | the node's own key |
| `bls_sig` | the node, over `"KONTOR_BLS_TO_XONLY_V1" ‖ x_only` |
| `registration_signature` | the node, over the `RegisterBlsKey` op (`nonce = 0`, `sponsored = true`) |

That leaves exactly one wallet prompt. Open `/admin` in a browser with the extension installed and unlocked, on the wallet account this node's BLS key was exported from — the node refuses a `bls_pubkey` that is not its own, since registering one would only produce the same `404` a restart later. The Portal gates registration on the operator's Taproot address being whitelisted; that table survives the Portal's own reset, and a `403 ADDRESS_NOT_WHITELISTED` is forwarded verbatim because only a Portal admin can clear it.

A node in [mnemonic mode](#mnemonic-mode) skips all of this: it holds the Taproot key too, so it fills in all five fields and registers itself during onboarding. The card then shows the account and the Taproot address to whitelist instead of the wallet button, since there is nothing left for a browser to sign.

An unregistered node also re-checks the Portal every 30 seconds, so a registration made anywhere else brings it back without anyone touching the container. On the same tick, a mnemonic node whose registration was refused offers it again — the request carries no nonce and no timestamp, so replaying it is signing nothing new. That is what makes whitelisting an address enough on its own: nobody but this process can register it, so if it stopped asking, the node would sit at `404` until someone restarted the container.

#### Restarting after a reset

The wipe does not re-register the node, and cannot: the `signer_id`, the JWT and the announced public URL are read once during onboarding and then held for the life of the process, and a signet reset invalidates all three. The full recovery is therefore:

1. reset the database with **restart the node after the wipe** ticked;
2. the node exits with code `75` and the supervisor starts it again, which re-runs onboarding, re-announces the URL and reconciles against the new chain;
3. if the Portal no longer knows the node's BLS key, onboarding stops at the registration card above instead of exiting — register from there and the node restarts again, this time onboarding cleanly.

Registering never issues `RegisterBlsKey` on-chain itself: the Portal's daemon batches that transaction, and onboarding waits for the resulting `signer_id` to appear.

Restarting also settles any download still in flight, which would otherwise write a file back after the wipe.

The exit code is deliberately non-zero: Railway's default policy and Docker Compose's `restart: on-failure` only bring back a container that failed, so a clean `0` would leave the node stopped.

The restart is offered only when `BLS_PASSWORD` or `KONTOR_STORAGE_MNEMONIC` is set. With neither, onboarding prompts for the key password on a terminal a restarted container does not have, so the node would go down and stay down — the checkbox is disabled and the API answers `400 RESTART_UNAVAILABLE`. Reset without it and restart the node yourself. A mnemonic node re-derives its key and never prompts, so it always qualifies.

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

