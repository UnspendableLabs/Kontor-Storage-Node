use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, boolean, json, string_len, timestamp_with_time_zone},
    sea_orm::{self, JsonValue},
};

/// Migration to create the agreements table
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Agreements::Table)
                    .if_not_exists()
                    .col(string_len(Agreements::AgreementId, 64).primary_key())
                    .col(string_len(Agreements::UserId, 64).not_null())
                    .col(string_len(Agreements::FileId, 64).not_null())
                    .col(string_len(Agreements::Filename, 255).not_null())
                    .col(string_len(Agreements::MimeType, 100).not_null())
                    .col(big_integer(Agreements::OriginalSize).not_null())
                    .col(
                        json(Agreements::Nodes)
                            .not_null()
                            .default(JsonValue::Array(Vec::new())),
                    )
                    .col(boolean(Agreements::Downloaded).not_null().default(false))
                    .col(string_len(Agreements::TransactionId, 64))
                    .col(json(Agreements::Curation))
                    .col(
                        string_len(Agreements::Status, 20)
                            .not_null()
                            .default("pending"),
                    )
                    .col(
                        timestamp_with_time_zone(Agreements::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agreements_user_status")
                    .table(Agreements::Table)
                    .col(Agreements::UserId)
                    .col(Agreements::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agreements_file_id")
                    .table(Agreements::Table)
                    .col(Agreements::FileId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agreements_status")
                    .table(Agreements::Table)
                    .col(Agreements::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_agreements_transaction")
                    .table(Agreements::Table)
                    .col(Agreements::TransactionId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Agreements::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Agreements {
    Table,
    AgreementId,
    UserId,
    FileId,
    Filename,
    MimeType,
    OriginalSize,
    Nodes,
    Downloaded,
    TransactionId,
    Curation,
    Status,
    CreatedAt,
}
