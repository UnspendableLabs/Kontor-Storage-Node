# Kontor Storage Node

[![CI](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/ci.yml/badge.svg)](https://github.com/UnspendableLabs/Kontor-Storage-Node/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/UnspendableLabs/Kontor-Storage-Node/graph/badge.svg?token=Rwusewkjbh)](https://codecov.io/gh/UnspendableLabs/Kontor-Storage-Node)
[![crates.io](https://img.shields.io/crates/v/kontor-storage-node.svg)](https://crates.io/crates/kontor-storage-node)
[![Licence](https://img.shields.io/crates/l/kontor-storage-node.svg)](#licence)

A storage node CLI for the Kontor distributed storage network. This node communicates with the Kontor Portal API to participate in the storage network.

A node stores files under contract, answers the Portal's challenges with BLS proofs, and submits an aggregated ledger. It needs no configuration file and no key material to start: give it an admin password, open `/admin` in a browser, and provision it from there.

## Prerequisites

- Rust 1.88 or later (the exact channel is pinned in [rust-toolchain.toml](rust-toolchain.toml))
- A running Kontor Portal instance

## Installation

From crates.io:

```bash
cargo install kontor-storage-node
```

From source:

```bash
git clone https://github.com/UnspendableLabs/Kontor-Storage-Node
cd Kontor-Storage-Node
cargo build --release
```

The binary will be available at `target/release/kontor-storage-node`.

## Usage

### Configuration

The node can be configured via command-line arguments or environment variables:

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--portal-url` | `PORTAL_API_URL` | `https://portal-application-develop.up.railway.app` | Portal API base URL. The default is the develop Portal, so an unconfigured node has something to register against; a production deployment sets this. |
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
| `--app-dir` | `KONTOR_APP_DIR` | Platform data dir (`/data` in Docker) | Where the keystore, the admin credential and the database live. **This is the one directory that must survive a restart.** |
| _(env only)_ | `KONTOR_SEAL_KEY` | _unset_ | Base64 key that opens this node's keystore. Optional: a node with none seals under a key it writes next to the keystore. See [Key sealing](#key-sealing). |
| _(env only)_ | `KONTOR_SETUP_TOKEN` | _unset_ | Setup token for claiming the admin UI. Optional: a node with none generates one and prints it. Setting it keeps the token out of the logs. At least 32 characters. See [First-run setup](#first-run-setup). |
| _(env only)_ | `ADMIN_UI_DISABLED` | _unset_ | Set to `1` to turn `/admin` off entirely. |
| `--bls-key-path` | `BLS_KEY_PATH` | `<data_dir>/Kontor-Storage-Node/bls_key.enc` | **Deprecated.** Path to a pre-keystore encrypted BLS key file, read once and migrated. For non-interactive migration, also set `BLS_PASSWORD`. |
| _(env only)_ | `KONTOR_STORAGE_MNEMONIC` | _unset_ | **Deprecated — set this node up from `/admin` instead.** A seed phrase here is read once, sealed into the keystore, and then no longer needed; remove it afterwards. See [Migrating an existing node](#migrating-an-existing-node). |
| _(env only, deprecated)_ | `KONTOR_STORAGE_ACCOUNT_INDEX` | `1` | Which account to derive when migrating from `KONTOR_STORAGE_MNEMONIC`, **numbered as Horizon Wallet numbers it: the first account is `1`**. Read once, at migration. New nodes choose the account in the setup wizard instead. |
| _(env only, deprecated)_ | `KONTOR_STORAGE_NETWORK` | `signet` | Network to derive against when migrating from `KONTOR_STORAGE_MNEMONIC`. Must match the Portal's own `PORTAL_BITCOIN_NETWORK`, or the derived address will never match its whitelist. New nodes choose it in the setup wizard. |
| _(env only, deprecated)_ | `KONTOR_STORAGE_REGISTER_NEW_ACCOUNT` | `0` | Only consulted on the `KONTOR_STORAGE_MNEMONIC` path. A node set up through the wizard needs no such override: it commits to one account once, having shown you the address it derived. |
| `--admin-password` | `ADMIN_PASSWORD` | _unset_ | Overrides the password chosen through `/admin`, and is the recovery path if it is forgotten. At least 16 characters. Leaving it unset is the normal case: the node mints a setup token instead. See [First-run setup](#first-run-setup). |
| `--kontor-contract-address` | `KONTOR_CONTRACT_ADDRESS` | `filestorage_0_0` | Kontor address of the filestorage contract. **Must match the Portal's own `KONTOR_CONTRACT_ADDRESS`**: the address is part of every signed Kontor op, so a mismatch makes the Portal reject every join and proof signature. |
| `--kontor-staking-contract-address` | `KONTOR_STAKING_CONTRACT_ADDRESS` | `staking_0_0` | Kontor address of the staking contract the node bonds its collateral in. **Must match the Portal's own `KONTOR_STAKING_CONTRACT_ADDRESS`**, for the same reason: it is part of every signed stake op. |
| `--auto-stake` | `KONTOR_STORAGE_AUTO_STAKE` | `true` | Bond spare KOR as collateral and claim storage rewards automatically. `false` (also `0`, `no`, `off`) makes the node sign no stake or claim op on its own. See [Staking & collateral](#staking--collateral). |
| `--gas-reserve-kor` | `KONTOR_STORAGE_GAS_RESERVE_KOR` | `5` | KOR kept liquid to pay the fees of the node's own joins and proofs. Never bonded. `0` bonds everything. |
| `--stake-target-kor` | `KONTOR_STORAGE_STAKE_TARGET_KOR` | _unset_ | Cap on the total bonded stake. Unset bonds everything above the gas reserve. |
| `--faucet-amount-kor` | `KONTOR_STORAGE_FAUCET_AMOUNT_KOR` | `1000` | KOR requested from the Portal faucet when the node starts with an empty balance. The Portal caps it (`PORTAL_FAUCET_MAX_AMOUNT_KOR`); a node asking for more is told the cap and asks again for exactly that. |
| `--claim-threshold-kor` | `KONTOR_STORAGE_CLAIM_THRESHOLD_KOR` | `1` | Claim storage rewards once at least this much is claimable (at most once an hour). |

All KOR amounts are exact decimals with up to 18 fractional digits (`2.5`,
`0.000000000000000001`); exponents and signs are refused rather than rounded.


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

When a `STORAGE_CAPACITY` is set, downloads are skipped if the next file would exceed the configured capacity, preserving disk space. When a `STORAGE_MAX_FILES` is set, the daemon stops fetching new agreements and downloading files once the stored file count reaches the limit — and keeps proving the ones it holds: a missed challenge is slashed.
When a `STORAGE_MAX_FILE_SIZE` is set, only agreements whose files are at or below that size are downloaded.

### First-run setup

A node needs no configuration to start. Run it, open `/admin`, and it walks you
through the rest:

1. **Start the node.** With nothing set it comes up serving `/admin`, prints a
   setup token, and waits.

   ```
   This node has not been claimed yet. Open /admin and enter this setup token to
   choose an admin password:

       150dc0e38dbd4c0133f30e2652180d4abaec42d3996e0d604eac0176abc6fb9f
   ```

   The token is also written to `.setup-token` in the application directory, and
   reprinted on every start until it is used — missing the first line does not
   lock you out. Set `KONTOR_SETUP_TOKEN` instead if you would rather it never
   appeared in your logs; the node then prints only a fingerprint, and `/admin`
   shows none.

2. **Claim the node.** Paste the token into `/admin` and choose an admin
   password (16 characters or more). It is stored as an Argon2id hash next to the
   keystore, and the token stops working the moment it is set.

3. **Give the node its identity.** Enter your Horizon Wallet seed phrase, the
   account number the wallet displays, and the network. The page encrypts the
   phrase in your browser before sending it — see [How the seed phrase
   travels](#how-the-seed-phrase-travels).

   The same form offers an optional **recovery password**. It is the only way
   back into the node's key if the file it is sealed with is ever lost, and this
   is the only moment it can be set from the browser — see [If the seal key is
   lost](#if-the-seal-key-is-lost). It is an *extra* way in, not a replacement,
   so a node that has one still restarts unattended.

4. **Whitelist the address.** The node shows the Taproot address it derived. A
   Portal admin has to whitelist it; until then the Portal answers
   `403 ADDRESS_NOT_WHITELISTED` and the node re-offers the same registration
   every 30 seconds. It starts on its own within a tick of the whitelisting —
   no restart, no second visit.

What the node keeps afterwards is a sealed BLS private key and a handful of
public values: the extended public key, the Taproot address, the node id, and the
Schnorr proof-of-possession signature. **The seed phrase is not among them.** It
exists inside the process for as long as it takes to derive a key and is then
discarded.

That is possible because a registration carries no nonce, no timestamp and no
challenge — it is a pure function of the two keys, and the Portal accepts the
same bytes forever. So the signature made once at setup keeps working, and a node
that threw its seed away registers exactly as well as one that kept it.

The two things it can no longer do without the seed are derive a *different*
account, and scan neighbouring accounts to diagnose a wrong account index. The
first is what running a second node is for; the second is not needed, because the
account is now chosen once, in a form that shows you the derived address and node
id before you commit them.

### How secrets travel between `/admin` and the node

TLS already covers the wire. It does not cover what happens at the ends of it: a
platform edge that logs request bodies, a proxy that buffers them, an APM agent
that samples them, an error reporter that serializes the whole exchange when
something downstream fails. None of that is an attack, and all of it ends with a
seed phrase in somebody's log store — permanently, since a seed phrase cannot be
rotated.

Three things move through `/admin` that must not appear in such a log, and they
move in both directions:

| Secret | Direction |
|---|---|
| the seed phrase, at setup | browser → node |
| the recovery password, at setup or when unlocking a sealed node | browser → node |
| the key for `KONTOR_SEAL_KEY`, when adding an env slot | node → browser |

All three go through one sealed envelope:

- the node mints an **ephemeral** P-256 keypair, in memory, for one use;
- the browser mints its own, does ECDH, and runs the shared secret through
  HKDF-SHA256 salted with the session id, expanded to **64 bytes**;
- those are two AES-256-GCM keys, one per direction, so a reply can never be
  replayed as a request;
- every seal uses the session id as additional authenticated data, which binds
  the ciphertext to the one envelope it was made for.

Everything is native WebCrypto — the page loads no scripts at all, and its
content-security policy forbids it from trying.

**What this does not defend against**, plainly: an attacker who controls the
*response* path. The envelope's public key is only as trustworthy as the admin
session that fetched it, and that session's token crosses the same proxy. This is
defence against passive capture, which is the failure that actually happens, not
against an active man in the middle. The one out-of-band check is the fingerprint:
the node logs it when the envelope is issued and the page shows it, so you can
compare them.

The page needs a secure context for `crypto.subtle` to exist at all — TLS, or
localhost. It says so rather than failing at the moment you press the button.

Both halves are tested. The node's half has its own tests, which play the client
in Rust; the browser's half is exercised by a harness that slices
`openEnvelope`, `sealRequest` and `openResponse` **verbatim** out of
`index.html` and drives them against a live binary under Node's WebCrypto:

```sh
cargo build && node scripts/envelope-harness.mjs
```

It starts a node with no configuration, claims it, sets it up through the sealed
channel, takes a seal key back out of it and adds a passphrase slot, then checks
that none of the three secrets appears in any body that crossed. What it cannot
cover is the page itself — no DOM, no CSP, no extension — so one manual pass over
a secure origin is still worth doing before a deployment is trusted.

### Key sealing

The BLS private key is sealed on disk with AES-256-GCM under a random data key.
That data key is itself wrapped once per **slot**, so there can be several ways
to open one keystore — the model LUKS and `age` use. Adding a way in is a small
write, not a re-encryption, and removing one does not invalidate the others.

| Slot | Where the key lives | Defends against | Does not defend against |
|---|---|---|---|
| `file` | `.seal-key`, beside the keystore | the **environment** leaking: `docker inspect`, `/proc/<pid>/environ`, a platform dashboard, a crash dump, an APM agent capturing the environment | anyone who can read the volume |
| `env` | `KONTOR_SEAL_KEY` | the **volume** leaking: a snapshot, a backup, a disk handed on | anyone who can read the environment |
| `passphrase` | nowhere — typed | both | unattended restarts; it can never be the only slot |

There is no ranking here, only different exposures. A node with nothing
configured uses the `file` slot, which is what makes zero configuration possible.
On a platform that holds both your environment and your volume, neither slot
defends against the platform itself.

The node logs a short fingerprint of the key it opened with on every start.
`GET /api/admin/seal` reports the same one. A **passphrase has none, by design**:
that response is not sealed, and four bytes of a hash of a secret a human chose
would let anyone who saw the body confirm guesses offline at one `SHA-256` each —
against the 64 MiB of Argon2id per guess that trying the keystore itself costs. A
random 32-byte key has no such weakness, which is why it is fingerprinted and a
passphrase is not.

What both do defend against is the thing being replaced. A stolen seal key plus a
stolen keystore yields **one node's signing key** — revocable, re-registerable,
and unable to move a coin. A leaked `KONTOR_STORAGE_MNEMONIC` yields the wallet:
every account, on every network, forever.

#### Hardening: moving the key into the environment

An operator task, not a browser one: `/admin` shows no seal-slot controls, and the
three calls below are made against the node's API with an admin session. Two
steps, with a redeploy in between, because the obvious one-step version is a door
that only opens one way.

1. `POST /api/admin/seal/env-slot` **generates a key for `KONTOR_SEAL_KEY`**. It
   comes back sealed to the caller, is returned once, and the node does not keep
   it. The file slot is untouched, so the node still starts exactly as before.
2. Set `KONTOR_SEAL_KEY` on the deployment and restart. The node records which
   slot it actually opened through.
3. Only once `GET /api/admin/seal` reports `env` does
   `POST /api/admin/seal/drop-file-slot` agree to **remove the seal key file**. By
   then the environment slot is not a claim — it is something the node has
   demonstrably started on.

A mistyped paste, a variable set on the wrong service, or a deploy that did not
pick it up therefore costs a retry rather than the key.

And it costs a retry rather than an outage, which is the point of leaving the
file slot in place for step 2. A `KONTOR_SEAL_KEY` that is malformed, or simply
not this keystore's, does not stop the node and does not even seal it: the node
falls back to the slot that does open, comes up normally, and says which source
failed —

```
! the env seal key did not open this keystore (…)
  The node opened through the file slot instead and is running normally.
    Correct the above before removing anything.
✓ Keystore opened (file slot, fingerprint 2bd8450f)
```

Falling back does not count as hardening. The record is *which slot this boot came
in through*, so a node that fell back still reports `file` and is still refused
step 3 — the fallback keeps the node up without ever letting a bad variable be
followed by deleting the key that still works.

Only when **nothing** on the machine opens the keystore does the node come up in
the `sealed` phase, serving `/admin` with the reason on the page. And only a
keystore that cannot be *parsed* is fatal — that one is an identity out of reach,
and carrying on there would offer the setup wizard a chance to provision a second
one over the top of it.

#### If the seal key is lost

Set the optional **recovery password** when the node is set up — that is where
`/admin` offers it, and it is the only screen that does. It is an additional slot,
not a replacement, so unattended restarts keep working. Without one, a node that
loses both its `.seal-key` and its `KONTOR_SEAL_KEY` starts in the `sealed` phase
and stays there: the key is there and nothing can open it.

With one, `/admin` on a sealed node offers to unlock it, and the node onboards
from there without restarting.

An already-running node that was set up without one can still be given a slot
through `POST /api/admin/seal/passphrase`, which takes it over the same sealed
envelope the browser uses.

A node rescued that way is running, but it is not one that can be restarted: the
slot it came up through is the passphrase, and nothing on the machine can supply
that at boot. `/admin` says so — the reset's restart checkbox stays disabled —
until a seal key is put back or a fresh one generated. Restore the key, or add an
env slot and redeploy, before treating the node as unattended again.

### Node phases

The server starts before the node knows anything about itself, so `/admin` is
reachable in every state. `GET /api/admin/status` reports which one:

| Phase | Meaning |
|---|---|
| `uninitialized` | No keystore. The setup wizard has the work. |
| `sealed` | A keystore exists and nothing here opened it — no key at all, or one that did not fit. `notice` says which. |
| `activating` | Keys in hand, talking to the Portal. |
| `unregistered` | The Portal has never heard of this key; the node keeps re-offering its registration. |
| `running` | Onboarded, daemon running. |
| `failed` | Activation failed. The server stays up so the reason can be read, and the node keeps retrying. |

Every transition happens **in the running process**. Completing setup, unsealing,
registering, or having an address whitelisted all move the node forward without
an exit and without a container restart.

`failed` is not a resting state. The commonest way to reach it is a Portal that
was not up in the second this node happened to start, which used to be answered
by exiting non-zero and letting the platform's restart policy try again — so the
supervisor now does that itself, retrying on a backoff from 30 s to 5 minutes and
naming the wait in `notice`. A node that reaches `running` on the third attempt
never needed anybody.

### Monitoring

That design has a consequence worth stating out loud: **the server answering is
no longer evidence that the node works.** A node waiting for its setup wizard, or
for a Portal admin to whitelist its address, or one whose activation failed,
serves `/api/info` and `/admin` exactly like a healthy one — deliberately, since
taking the server down would remove the only page explaining what is wrong.

So the container health check (`GET /api/info`, in the Dockerfile) is a
*liveness* check and nothing more. Whether the node is doing its job is a
separate question, answered by the same endpoint without authentication:

```json
{ "node_id": "node-…", "phase": "running", "serving": true }
```

Alert on `serving` being false, or on `phase` staying anything but `running`.
`unregistered` and `uninitialized` are states a node can sit in indefinitely and
correctly — they need a person, not a restart. `failed` retries itself, so alert
on it *persisting* rather than on it appearing.

### Migrating an existing node

A node that already runs on `KONTOR_STORAGE_MNEMONIC`, or on a `bls_key.enc` plus
`BLS_PASSWORD`, migrates itself on the next start. It seals the key it already
has into a keystore, keeps the same identity and node id, and says so:

> **The one place the server does not start first.** Migration happens before the
> HTTP listener opens, because it is what decides which node this is. A
> `bls_key.enc` whose `BLS_PASSWORD` is wrong or unset therefore still stops the
> node with no `/admin` to explain it — the key file needs that password and a
> container has no terminal to prompt at. Check the variable before deploying
> this release. Once the migration has run, the password is never needed again.

```
No keystore yet, but this node has key material from an older release. Migrating it into one.
  It will be sealed into /data/keystore.json (file slot, fingerprint 2bd8450f) once the Portal has accepted this identity.
Onboarding as node-2bd8… (account 2, signet)
✓ Sealed into /data/keystore.json (file slot, fingerprint 2bd8450f)
  KONTOR_STORAGE_MNEMONIC is no longer needed and should be removed from this deployment.
```

Nothing else changes: same key, same node id, same agreements.

**The keystore is written after onboarding, not before**, and the order is
deliberate. The one thing that catches a mistyped `KONTOR_STORAGE_ACCOUNT_INDEX`
is the check against the accounts this mnemonic already has registered, and that
check needs the Portal — so it runs during onboarding, after the derivation. A
node that sealed first would have committed the wrong account to a file that
outranks the variable from then on: correcting the variable would change nothing,
and the next start would open the keystore, find no seed phrase to scan with, and
register the very identity the check had refused. So a refused account is never
written down, and the fix really is to correct the variable and start again.

Sealing happens on both outcomes onboarding can reach — a node that is running,
and one waiting for a Portal admin to whitelist its address. Only an outright
refusal leaves the volume untouched.

**Then confirm the keystore is on durable storage before removing the variable,
in that order.** The keystore is written to `KONTOR_APP_DIR` — `/data` in Docker
— which is the directory a deployment is supposed to mount a volume over. If it
turns out not to be one, the keystore is gone at the next deploy, and by then the
mnemonic that could have rebuilt it has been deleted too. One restart tells you:

1. Deploy this release and look for the `✓ Sealed into …` line above.
2. Restart once with `KONTOR_STORAGE_MNEMONIC` still set. The node must now print
   `✓ Keystore opened (file slot, fingerprint …)` — the same fingerprint, and no
   second migration.
3. Only then remove the variable.

Step 2 costs a restart and is the whole of the safety net: a node that reports
opening the keystore it wrote has proved the file survives a deploy.

The keystore wins from that point on, unconditionally. A `KONTOR_STORAGE_MNEMONIC`
left behind cannot move a running node to another identity — if it derives a
different one the node logs an error naming both and keeps its own. The legacy
`bls_key.enc` is left exactly where it is; deleting an operator's key file is not
the node's call to make.

**One thing changes for a node that was running without `ADMIN_PASSWORD`.** Until
now that meant `/admin` rendered and nothing behind it could be unlocked, which
was a coherent default while the UI was an optional convenience. It is not one
now that the UI is how a node is configured, so such a node comes back
*unclaimed*: it mints a setup token, writes it to `.setup-token` (mode `0600`)
beside the keystore, and prints it on every start until somebody claims it.

Whoever can read those logs or that volume can therefore claim the admin UI, and
from there reset the database, re-register the node, or be handed a seal key. The
*volume* half of that is the same trust boundary as the file seal slot, so it
moves no line that was not already there. The *log* half is worth a second look
before this release is deployed: a log aggregator is usually readable by more
people than a volume is, and until this release nothing an operator could do from
`/admin` was reachable on such a node at all. Three ways to decide it deliberately
rather than inherit it:

- Set `ADMIN_PASSWORD` (at least 16 characters). It overrides anything stored and
  no token is minted.
- Set `KONTOR_SETUP_TOKEN` to a secret of your own, at least 32 characters. Only
  its fingerprint is ever logged. This trades a secret in the log stream for one
  in the environment; it is a choice of which exposure, not an escape from both.
  Note that 32 characters is a length rule and not an entropy one — use something
  a generator produced, not a sentence. `/admin` does not publish the fingerprint
  of a supplied token for that reason, so the claim screen shows none.
- Set `ADMIN_UI_DISABLED=1` if this node is not meant to be administered from a
  browser at all. Nothing behind `/admin` then opens, including the setup wizard.

### Deriving from a seed phrase

Derivation matches Horizon Wallet exactly — BIP-39 with an empty passphrase, then
`m/12381/{coin}/{index}/0` for the BLS key via EIP-2333 and
`m/86'/{coin}'/{index}'/0/0` for the Taproot key, where `{index}` is the account
number minus one. A node set up from a seed phrase and a wallet-exported one on
the same account are the same node.

Accounts are numbered the way the wallet displays them: "Account 2" in Horizon
Wallet is `2`. The derivation paths count from 0 — account 2 is the key at child
index 1 — but that offset is the node's business, not the operator's, and it is
applied in one place. `0` is refused rather than read as the first account, since
it is what someone types who believes this counts from 0, and every account they
meant would then be off by one.

#### Running several nodes from one mnemonic

One mnemonic backs as many nodes as it has accounts — one node per account. Set
each one up through its own `/admin`, choosing a different account number. The
wizard shows the derived Taproot address and node id before you commit them,
which is the check that matters: a node is now given its account once, deliberately,
rather than re-reading a variable on every boot that a typo could change.

Each node also records the identity it came up with in
`<storage_dir>/.node-identity.json`. A later `404` on that same identity reads as
"the Portal forgot me" rather than "this account was never right", which is what
lets every node of a multi-node deployment recover unattended from a Portal reset
rather than only the one that restarted first.

### Staking & collateral

Kontor will not let a node store anything it has not put money behind. Joining
an agreement requires a **bonded stake** in the `staking` contract whose
*unreserved* part covers the agreement's `required_collateral`; the join then
reserves that amount until the membership ends. Every challenge the node fails
to answer before its deadline is settled by **slashing 30 × the agreement's
collateral** from the stake.

#### What the node does on its own

Each sync cycle the node reads its bond from the Portal (`GET
/api/signers/{signer_id}` — the same request that resyncs its nonce) and:

1. **Bonds spare KOR.** If at least 1 KOR sits above the gas reserve
   (`KONTOR_STORAGE_GAS_RESERVE_KOR`, 5 by default) it signs
   `add-stake(min(free, target − stake))` and hands it to the Portal, which
   publishes it like a join. A fresh node does this right after the faucet funds
   it — 1000 KOR by default, so 995 bonded — before it looks at any agreement.
2. **Joins only what the bond covers.** Before downloading a ready agreement it
   checks the agreement's collateral against the unreserved stake, less what
   this cycle and still-unexecuted earlier joins have already committed. An
   agreement whose collateral the Portal does not know yet is left for a later
   cycle. Nothing it cannot join is downloaded.
3. **Claims rewards** once `KONTOR_STORAGE_CLAIM_THRESHOLD_KOR` (1 KOR) is
   claimable, at most hourly, so the next cycle bonds them.

The node sends **one** stake or claim op at a time. The Portal only answers
"queued", so the node learns that an op ran from its nonce: once Kontor's
`next_nonce` moves past it, the op has executed, and the next decision is made
from the balance and stake the Portal then reports. An op that is never
reflected is given up after 30 minutes and decided again. The stake op is the
last thing a cycle signs, so it never takes a nonce a proof needed.

The gas reserve is not optional in spirit: the node pays its own fees, and a
node with nothing liquid cannot submit proofs — which is the expensive way to
run out of money. Set `KONTOR_STORAGE_AUTO_STAKE=false` to manage the bond by
hand; joins are still gated on whatever stake there is.

Against a Portal that predates staking (its signer entry reports no stake) the
node behaves as it always did: no stake ops, no gating. Once a Portal *has*
reported a stake, a cycle in which it cannot be read joins nothing.

#### Slashing risk

A miss costs 30 × the agreement's collateral, so a node holding many agreements
can lose its whole bond to a short outage. The node defends what it can:

- proofs run every cycle, including on a node at `STORAGE_MAX_FILES` or one
  whose join was just refused, nearest deadline first;
- a proof Kontor rejects leaves the challenge open, and the node proves it again
  — up to 5 times, 1 to 16 minutes apart — before giving up loudly on a proof
  that is evidently wrong;
- a refused join (`422` from the Portal) no longer fails the cycle; joins pause
  for 10 minutes instead.

It cannot defend against being down, against a file it lost, or against the
[ledger limitation](#the-aggregated-ledger) below, which stops every proof at
once. `GET /api/admin/status` and the **Collateral** card in `/admin` show the
bond as the daemon last read it; a drop in stake is logged at `ERROR` as a
slash.

#### Bond cleanup, and coming back from it

If slashing takes the stake to zero, Kontor puts the node in **bond cleanup**:
it stops its rewards, settles its open challenges and removes it from its
agreements, a bounded amount of work per block. Until that finishes the node
can **neither join nor add stake** — Kontor refuses both, so the node does not
try. `/admin` says so, and the log says so once when it starts.

Nothing needs doing while it runs. When cleanup clears, the next cycle sees an
empty bond with KOR above the reserve (fund the node again if the faucet will
not), stakes it, and starts joining as a new node would. Before that, find out
why challenges were missed — a node slashed into cleanup once will be again.

#### Leaving

`/admin` → **Withdraw the collateral** queues `begin-unstake` or
`withdraw-stake` for the daemon to sign (type `UNSTAKE` / `WITHDRAW` to
confirm). An unstake starts Kontor's withdrawal delay (about two weeks of
blocks) and stops every new join and top-up for good, but the node must keep
proving what it holds. The withdrawal succeeds only once the delay has passed
and no agreement or open challenge holds any of the bond.

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
- MySQL must be 8.0.13 or later. The `agreements` table has JSON columns with
  defaults, and that is the release where MySQL started accepting a default on
  a JSON column at all. CI runs the migrations against a real Postgres and a
  real MySQL on every push, so this is a tested claim rather than a hopeful one.

#### Running migrations manually

```bash
./kontor-storage-node migrate up          # apply all pending
./kontor-storage-node migrate status      # list each migration and its state
./kontor-storage-node migrate down -n 1   # roll back the last one
```

`migrate` reads `--database-url`/`DATABASE_URL` like every other command and
touches nothing else, so it can be pointed at a database from a machine that is
not the node — which is the usual way to run the schema change before the
deploy rather than during it.

### Commands

#### Ping

Check connectivity with the Portal API:

```bash
./kontor-storage-node ping
```

Or with a custom portal URL:

```bash
./kontor-storage-node --portal-url https://portal.example.com/api ping
```

Using environment variable:

```bash
export PORTAL_API_URL=https://portal.example.com/api
./kontor-storage-node ping
```

### HTTP Server

When the daemon runs (`./kontor-storage-node run`), it exposes a public HTTP server on `0.0.0.0:8081` by default (override via `--server-address` or `SERVER_ADDRESS`) for serving downloaded files and a dashboard.

Endpoints:

| Path | Description |
|------|-------------|
| `GET /` | HTML dashboard listing stored files |
| `GET /api/info` | JSON: `{ "node_id": ..., "phase": ..., "serving": ... }` — see [Monitoring](#monitoring) |
| `GET /files?offset=&limit=` | JSON: paginated list of stored files |
| `GET /files/:file_id` | Download (local backend) or 307 redirect to a GCS signed URL |
| `GET /static/*` | Static assets (logo, dashboard CSS/JS) |
| `GET /admin` | Operator UI (password-gated, see below) |
| `GET /api/admin/bootstrap` | Which screen to render: claimed, enabled, phase, setup-token fingerprint (no session) |
| `POST /api/admin/claim` | Trade the setup token for an admin password, and get a session (no session) |
| `POST /api/admin/login` | Exchange the admin password for an 8-hour session token |
| `GET /api/admin/status` | JSON: row counts, storage summary and registration state (session required) |
| `POST /api/admin/reset-database` | Wipe the node's database, optionally restarting the node (session required) |
| `POST /api/admin/register-node` | Register the node's BLS key on the Portal and onboard again in place (session required) |
| `GET /api/admin/envelope` | Mint a one-shot sealed channel for the secrets below (session required) |
| `POST /api/admin/setup/provision` | Give an unconfigured node its identity, from a sealed seed phrase and an optional sealed recovery password (session required) |
| `POST /api/admin/seal/env-slot` | Add a `KONTOR_SEAL_KEY` slot; the key comes back sealed. Operator API — `/admin` does not call it (session required) |
| `POST /api/admin/seal/drop-file-slot` | Remove `.seal-key`, once the node has booted on the env slot. Operator API — `/admin` does not call it (session required) |
| `POST /api/admin/seal/passphrase` | Add a slot only a human can open, from a sealed passphrase. Operator API — `/admin` sets one at setup instead (session required) |
| `POST /api/admin/unseal` | Open a sealed node with a sealed passphrase (session required) |

CORS is permissive (`Access-Control-Allow-Origin: *`) on the serving routes, which are all public — see [`src/server/routes.rs`](src/server/routes.rs) for the security model. The `/admin` routes are deliberately outside that CORS layer and carry their own password gate. See [`apiary.apib`](apiary.apib) for the full API specification.

### Operator UI

`/admin` is a single-page operator UI, and on a fresh node it is also the only way
to configure one — see [First-run setup](#first-run-setup). It is protected as
follows:

- the password is exchanged at `POST /api/admin/login` for a session token that expires after 8 hours and is held in `sessionStorage`, never a cookie;
- an unclaimed node answers `409 ADMIN_NOT_CLAIMED` instead, and `POST /api/admin/claim` trades the setup token for a password;
- the chosen password is stored as an Argon2id hash (OWASP's interactive profile, not the 64 MiB at-rest one: this hash is checked online behind a throttle, and 64 MiB per attempt would be a memory-exhaustion lever rather than a defence);
- `ADMIN_PASSWORD` overrides the stored password and is the recovery path if it is forgotten; `ADMIN_UI_DISABLED=1` turns the UI off entirely;
- the token is signed with a key generated at startup and never persisted, so restarting the node ends every session;
- failed logins from a client the node can tell apart are throttled per peer IP (10 per 15 minutes) with a fixed 250 ms delay on each rejection, and the password is compared in constant time;
- failed *claims* are counted separately and never lock the door: they cost an escalating delay capped at 2 s instead. A setup token is 32 bytes of entropy, so grinding it is not a threat worth a lockout — whereas on an unclaimed node a lockout would let anyone who can reach the node decide it never gets configured at all;
- `X-Forwarded-For` is not trusted — a spoofable header would hand an attacker unlimited buckets — so behind a reverse proxy every client shares one throttle bucket. **A lockout is only ever applied to a bucket that belongs to one client.** Locking a shared one would let any stranger keep the operator out of the only page that can administer the node, which is the same failure the claim gate avoids and worse, since there is no second channel to recover through. A proxied deployment pays the escalating delay instead: the budget stops being a door that closes and becomes a rate, capped at one guess every two seconds. What that costs is that such a deployment can be ground at that rate indefinitely, which is why the password floor is 16 characters and why giving the node real client addresses is worth doing;
- Argon2 verification runs off the async executor, so a burst of login attempts cannot park the threads serving everything else.

Beyond first-run setup, the UI shows what the node holds and offers: **register
the node on the Portal**, **reset the database**, and the [key sealing](#key-sealing)
controls.

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

A node set up through the wizard skips all of this: it recorded the Schnorr signature at setup, so it fills in all five fields and registers itself during onboarding. The card then shows the account and the Taproot address to whitelist instead of the wallet button, since there is nothing left for a browser to sign. Only a node migrated from a bare `bls_key.enc` — which never had a Taproot account — still needs the wallet.

An unregistered node also re-checks the Portal every 30 seconds, so a registration made anywhere else brings it back without anyone touching the container. On the same tick, a node whose own registration was refused offers it again — the request carries no nonce and no timestamp, so replaying it is signing nothing new. When either lands, the node onboards **in the running process**: no exit, no restart. That is what makes whitelisting an address the whole of the operator's work.

The same property bounds the retry. Identical bytes get an identical answer, so a Portal that read the registration and rejected it — `400`, `401`, `409`, `422` — will say the same thing forever; the node logs that once at `error` level and stops offering it, while continuing to watch for a registration made elsewhere. Only refusals the request itself cannot be blamed for are replayed: `403 ADDRESS_NOT_WHITELISTED` above all, plus timeouts, rate limits and `5xx`.

#### Restarting after a reset

The wipe does not re-register the node, and cannot: the `signer_id`, the JWT and the announced public URL are read once during onboarding and then held for the life of the process, and a signet reset invalidates all three. The full recovery is therefore:

1. reset the database with **restart the node after the wipe** ticked;
2. the node exits with code `75` and the supervisor starts it again, which re-runs onboarding, re-announces the URL and reconciles against the new chain;
3. if the Portal no longer knows the node's BLS key, onboarding lands in the `unregistered` phase instead of exiting — register from the card above, and the node onboards again in the same process, with no further restart and no second sign-in.

Registering never issues `RegisterBlsKey` on-chain itself: the Portal's daemon batches that transaction, and onboarding waits for the resulting `signer_id` to appear.

Restarting also settles any download still in flight, which would otherwise write a file back after the wipe.

The exit code is deliberately non-zero: Railway's default policy and Docker Compose's `restart: on-failure` only bring back a container that failed, so a clean `0` would leave the node stopped.

The restart is offered only when a restarted process could actually get back up: the keystore must have a slot the machine itself can supply (`file` or `env`). A node whose only slot is a passphrase would come back sealed and wait for a human, so restarting it would be an outage rather than a recovery — the checkbox is disabled and the API answers `400 RESTART_UNAVAILABLE`. Reset without it and restart the node yourself.

## Development

```bash
# Run in development mode
cargo run -- ping

# Run with custom portal URL
cargo run -- --portal-url http://localhost:3000 ping

# Run pointing to a specific database
cargo run -- --database-url sqlite://./local.db ping
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test and lint commands CI runs,
and for the pre-commit hook that runs them before you push.

## Contributing

Issues and pull requests are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md).

Found a security problem? Please do not open a public issue — see
[SECURITY.md](SECURITY.md).

## Licence

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT licence ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this work, as defined in the Apache-2.0 licence, shall be
dual-licensed as above, with no additional terms or conditions.

