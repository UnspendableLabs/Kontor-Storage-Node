//! Database migrations for Kontor Storage Node.
//!
//! Keep migrations ordered here so they are applied sequentially.

pub use sea_orm_migration::prelude::{MigrationTrait, MigratorTrait};

pub mod m20250127_000001_create_challenges_table;
pub mod m20251217_000001_create_agreements_table;
pub mod m20260727_000001_add_ledger_fields_to_agreements;

/// Migrator orchestrates the ordered list of migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20251217_000001_create_agreements_table::Migration),
            Box::new(m20250127_000001_create_challenges_table::Migration),
            Box::new(m20260727_000001_add_ledger_fields_to_agreements::Migration),
        ]
    }
}
