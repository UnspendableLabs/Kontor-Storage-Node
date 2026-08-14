//! Adds the `object_id` and `ledger_index` columns to `agreements`.
//!
//! Both come from the on-chain file descriptor and are needed to reproduce, bit
//! for bit, the `FileMetadata`/ledger view the filestorage contract verifies a
//! Proof-of-Retrievability against (kontor-crypto 0.3.0):
//!
//! - `object_id` is the descriptor's `object-id` (`obj_<sha256>` of the file
//!   contents). `FileMetadata::validate` requires it to be non-empty, and it is
//!   mirrored from the Portal rather than recomputed so the node's descriptor
//!   stays the one the contract published. (`Challenge::id()` itself hashes
//!   `file_id`/`nonce`/`padded_len`/`original_size`/`root`, not `object_id`.)
//! - `ledger_index` is the stable, append-only slot the contract assigned the
//!   file. Since 0.3.0 the ledger is append-only and this slot is a public input
//!   of the SNARK, resolved by the prover from its own `FileLedger` and by the
//!   contract from its registry. A file sitting at a different local index
//!   yields proofs that never verify.
//!
//! Both are nullable: the Portal only knows `ledger_index` once the creating
//! transaction has been reconciled against Kontor, and rows predating this
//! migration are backfilled on the next agreement sync.
use sea_orm_migration::{
    prelude::{DbErr, DeriveIden, DeriveMigrationName, MigrationTrait, SchemaManager, Table},
    schema::{big_integer_null, string_len_null},
    sea_orm,
};

/// Migration adding the ledger-related descriptor fields to `agreements`.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    // SQLite only accepts one alteration per ALTER TABLE, so each column gets
    // its own statement rather than a single chained `alter_table`.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agreements::Table)
                    .add_column(string_len_null(Agreements::ObjectId, 128))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Agreements::Table)
                    .add_column(big_integer_null(Agreements::LedgerIndex))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agreements::Table)
                    .drop_column(Agreements::ObjectId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Agreements::Table)
                    .drop_column(Agreements::LedgerIndex)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Agreements {
    Table,
    ObjectId,
    LedgerIndex,
}
