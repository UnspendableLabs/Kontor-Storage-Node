//! Database migrations for Kontor Storage Node.
//!
//! Keep migrations ordered here so they are applied sequentially.
//!
//! These used to be a separate `migration` crate driven by `sea-orm-cli`.
//! They live in the binary now because a path dependency cannot be published
//! to crates.io, and a second crate on the registry would only exist to be
//! version-locked to this one. The `migrate` subcommand replaces the old
//! `cargo run -p migration -- …` for the databases that need it (Postgres and
//! MySQL); SQLite still migrates itself on connect.

pub use sea_orm_migration::prelude::{MigrationTrait, MigratorTrait};
pub use sea_orm_migration::MigrationStatus;

pub mod m20250127_000001_create_challenges_table;
pub mod m20251217_000001_create_agreements_table;
pub mod m20260727_000001_add_ledger_fields_to_agreements;
pub mod m20261104_000001_create_node_state_table;

/// Migrator orchestrates the ordered list of migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20251217_000001_create_agreements_table::Migration),
            Box::new(m20250127_000001_create_challenges_table::Migration),
            Box::new(m20260727_000001_add_ledger_fields_to_agreements::Migration),
            Box::new(m20261104_000001_create_node_state_table::Migration),
        ]
    }
}
