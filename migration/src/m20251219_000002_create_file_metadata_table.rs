use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, string_len, timestamp_with_time_zone},
    sea_orm,
};

/// Migration to create the file_metadata table storing FileMetadata rows.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(FileMetadata::Table)
                    .if_not_exists()
                    .col(string_len(FileMetadata::Id, 64).primary_key())
                    .col(string_len(FileMetadata::AgreementId, 64).not_null())
                    .col(string_len(FileMetadata::Filename, 255).not_null())
                    .col(string_len(FileMetadata::Root, 128).not_null())
                    .col(string_len(FileMetadata::FileId, 64).not_null())
                    .col(big_integer(FileMetadata::OriginalSize).not_null())
                    .col(big_integer(FileMetadata::PaddedLen).not_null())
                    .col(
                        timestamp_with_time_zone(FileMetadata::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_file_metadata_agreement")
                            .from(FileMetadata::Table, FileMetadata::AgreementId)
                            .to(Agreements::Table, Agreements::AgreementId)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_file_metadata_agreement_unique")
                    .table(FileMetadata::Table)
                    .col(FileMetadata::AgreementId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_file_metadata_file_id")
                    .table(FileMetadata::Table)
                    .col(FileMetadata::FileId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FileMetadata::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum FileMetadata {
    Table,
    Id,
    AgreementId,
    Filename,
    Root,
    FileId,
    OriginalSize,
    PaddedLen,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Agreements {
    Table,
    AgreementId,
}
