# Kontor-Crypto prep plan (actionable, no decisions left)

Context: Use kontor_crypto 0.1.3 to process every downloaded agreement
file so it is provable later. We must persist raw bytes, FileMetadata,
and an aggregated ledger at `<storage_dir>/ledger.bin`. PreparedFile is
discarded.

- [x] Add dependency
  - Update Cargo.toml: add `kontor_crypto = "0.1.3"` with ledger features
    if gated (enable what exposes `api::prepare_file` and `FileLedger`).
  - Run `cargo metadata`/`cargo check` once added.

- [x] Define persistence model (new table)
  - Create table `file_metadata` (SeaORM entity + migration):
    - `id` TEXT PRIMARY KEY (could use `file_id` from metadata).
    - `agreement_id` TEXT NOT NULL REFERENCES agreements.agreement_id.
    - `filename` TEXT NOT NULL (from portal/metadata).
    - `root` TEXT NOT NULL (from FileMetadata).
    - `file_id` TEXT NOT NULL (dup of id for clarity; keep both or set id
      = file_id; choose one in migration and align entity).
    - `original_size` BIGINT NOT NULL.
    - `padded_len` BIGINT NOT NULL.
    - `created_at` TIMESTAMPTZ NOT NULL DEFAULT now().
  - Add unique index on `agreement_id` (1-1 mapping).
  - Ensure migration is idempotent (if_not_exists where applicable).

- [x] Wire storage path for ledger
  - Use `<storage_dir>/ledger.bin` (config-free constant).
  - Ensure parent dir exists; reuse download storage dir.

- [x] Update download pipeline in `src/tasks/downloadagreements.rs`
  - After successful download:
    - Read file bytes from `<storage_dir>/<file_id>`.
    - Call `kontor_crypto::api::prepare_file(&bytes, filename)` -> `(PreparedFile, FileMetadata)`.
    - Drop PreparedFile immediately.
    - Persist FileMetadata into `file_metadata` table (insert or upsert
      by agreement_id/file_id to stay idempotent).
    - Load ledger from `<storage_dir>/ledger.bin` if exists else
      `FileLedger::new()`.
    - `ledger.add_file(&metadata)` then `ledger.save(path)`.
    - Mark agreement as downloaded/prepared (existing downloaded flag can
      remain; consider new boolean `prepared` or reuse downloaded if both
      actions are atomic—if new column needed, add in migration).
  - Error handling:
    - If ledger/metadata persistence fails, keep file but do not mark as
      downloaded/prepared; surface error so retry will process again.
    - Retain existing capacity/max_files checks before download.

- [x] Add SeaORM entity for `file_metadata`
  - Generate/hand-write entity matching migration.
  - Expose via `entities::prelude`.

- [x] Tests
  - Unit/integration:
    - Migration creates table with indexes.
    - downloadagreements flow: after download, FileMetadata row exists,
      ledger file exists, PreparedFile not persisted.
    - Idempotent rerun: same agreement/file_id does not duplicate rows;
      ledger remains consistent.
    - Failure path: simulate ledger.save failure -> agreement not marked
      prepared, row not partially written.
  - Update existing download tests to assert metadata row + ledger file.

- [x] Docs
  - Add README section describing post-download pipeline: download ->
    prepare_file -> store FileMetadata -> update ledger at
    `<storage_dir>/ledger.bin` -> drop PreparedFile.
  - Mention retry/idempotency behavior and schema fields stored.

