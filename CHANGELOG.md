# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-14

First public release.

### Added

- Storage node daemon for the Kontor network: polls the Portal for agreements,
  downloads the files they cover, answers challenges with BLS proofs, and
  submits an aggregated ledger.
- Zero-configuration onboarding. A node with nothing but an admin password
  starts, serves `/admin`, and is provisioned from the browser — key
  generation, registration, whitelist request and unlock all happen in-process,
  with no restart.
- Identity derived from a BIP-39 mnemonic, byte-compatible with Horizon Wallet.
  One mnemonic can back several nodes through the account index.
- Sealed admin channel: secrets travel between the browser and the node under
  P-256 ECDH + HKDF + AES-GCM, on a page that loads no external script.
- Encrypted keystore with Argon2 key derivation, and an optional seal key that
  can be moved into the environment so an unattended node comes back without
  an operator.
- Storage backends: local filesystem and Google Cloud Storage, with capacity,
  file-count and per-file size limits.
- Public HTTP server for file downloads, a status dashboard, and a
  password-gated operator UI at `/admin`.
- `migrate` subcommand for the databases that do not migrate themselves
  (Postgres, MySQL). SQLite still migrates on connect.

[Unreleased]: https://github.com/UnspendableLabs/Kontor-Storage-Node/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/UnspendableLabs/Kontor-Storage-Node/releases/tag/v0.1.0
