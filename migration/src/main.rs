use sea_orm_migration::{cli, prelude::MigratorTrait};

#[tokio::main]
async fn main() {
    cli::run_cli(migration::Migrator).await;
}
