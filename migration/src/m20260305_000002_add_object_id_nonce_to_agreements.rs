use sea_orm_migration::{
    prelude::{DbErr, DeriveIden, DeriveMigrationName, MigrationTrait, SchemaManager, Table},
    schema::string_len,
    sea_orm,
};

/// Migration to add optional proof-related metadata to the agreements table.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agreements::Table)
                    .add_column_if_not_exists(string_len(Agreements::ObjectId, 128).null())
                    .add_column_if_not_exists(string_len(Agreements::NonceHex, 512).null())
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
                    .drop_column(Agreements::NonceHex)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Agreements {
    Table,
    ObjectId,
    NonceHex,
}
