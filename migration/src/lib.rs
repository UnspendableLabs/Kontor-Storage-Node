//! Database migrations for Kontor Storage Node.
//!
//! Keep migrations ordered here so they are applied sequentially.

pub use sea_orm_migration::prelude::{MigrationTrait, MigratorTrait};

pub mod m20251217_000001_create_agreements_table;

/// Migrator orchestrates the ordered list of migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(
            m20251217_000001_create_agreements_table::Migration,
        )]
    }
}
