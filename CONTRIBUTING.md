# Contributing

Thanks for taking an interest. This is the storage node for the Kontor
network; it talks to a Portal, so most changes are easier to reason about with
[the README](README.md) open — particularly the sections on node phases and on
how secrets travel between `/admin` and the node.

## Getting set up

The toolchain is pinned in [rust-toolchain.toml](rust-toolchain.toml); rustup
will pick it up on its own.

```bash
cargo build
cargo test --workspace --all-targets --all-features --locked
```

Install the pre-commit hook so you find out about a formatting or lint failure
before CI does:

```bash
git config core.hooksPath .githooks
```

It runs the same three commands the `fmt`, `clippy` and `test` CI jobs run.

## What CI checks

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-targets --all-features --locked`
- `node scripts/envelope-harness.mjs` — the browser half of the sealed admin
  channel. `cargo test` cannot reach it: the Rust tests play the client in Rust
  and pin the WebCrypto names, but neither runs the page's own code. This
  harness slices the three functions out of `index.html` and drives them
  against a live binary. If you touch the sealed envelope on either side, run
  it locally.
- `scripts/migrate-backends.sh` — the migrations against a real Postgres and a
  real MySQL. `cargo test` runs them on SQLite only, so a statement that SQLite
  accepts and another server does not passes everything else. If you add or
  change a migration, this is the job that has an opinion about it.
- `cargo check` on the `rust-version` in Cargo.toml. Every other job resolves
  its toolchain through [rust-toolchain.toml](rust-toolchain.toml), so the
  declared minimum is only ever compiled by this one.
- `cargo llvm-cov` — coverage is gated at 95%. New code needs tests.

## Working on the crypto paths

The node is the prover and the filestorage contract is the verifier, so
`kontor-crypto` must be the *same* version Kontor's indexer and the Horizon
Portal resolve. A version skew produces proofs that never verify, and nothing
in this repository's tests will tell you. Bumping it is a coordinated change
across three repositories, not a dependency update.

## Commits and pull requests

- Keep a pull request to one change. A rename that touches forty files is its
  own commit, separate from the behaviour change hiding among them.
- Write the commit subject as what the change does, not what you did.
- Update [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]` for anything an
  operator would notice.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are dual-licensed under MIT and Apache-2.0, matching the project.
Submitting a pull request means you agree to that.
