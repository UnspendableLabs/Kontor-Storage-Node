use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, string, string_len, timestamp_with_time_zone},
    sea_orm,
};

/// Migration to create the challenges table
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Challenges::Table)
                    .if_not_exists()
                    .col(string_len(Challenges::ChallengeId, 128).primary_key())
                    .col(string_len(Challenges::AgreementId, 64).not_null())
                    .col(big_integer(Challenges::BlockHeight).not_null())
                    .col(big_integer(Challenges::ChallengeCount).not_null())
                    .col(string(Challenges::Seed).not_null())
                    .col(string_len(Challenges::ProverId, 64).not_null())
                    .col(big_integer(Challenges::DeadlineHeight).not_null())
                    .col(
                        string_len(Challenges::Status, 20)
                            .not_null()
                            .default("active"),
                    )
                    .col(string(Challenges::Proof).null())
                    .col(string(Challenges::BlsSignature).null())
                    .col(
                        timestamp_with_time_zone(Challenges::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(Challenges::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_challenges_agreement")
                            .from(Challenges::Table, Challenges::AgreementId)
                            .to(Agreements::Table, Agreements::AgreementId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_challenges_prover_status")
                    .table(Challenges::Table)
                    .col(Challenges::ProverId)
                    .col(Challenges::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_challenges_agreement_id")
                    .table(Challenges::Table)
                    .col(Challenges::AgreementId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_challenges_status")
                    .table(Challenges::Table)
                    .col(Challenges::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_challenges_deadline_height")
                    .table(Challenges::Table)
                    .col(Challenges::DeadlineHeight)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Challenges::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Challenges {
    Table,
    ChallengeId,
    AgreementId,
    BlockHeight,
    ChallengeCount,
    Seed,
    ProverId,
    DeadlineHeight,
    Status,
    Proof,
    BlsSignature,
    CreatedAt,
    UpdatedAt,
}

/// Identifier mirror for the agreements table so we can reference it as the FK
/// target without making the agreements migration's private `Agreements` enum
/// pub. Only the column needed for the FK target is declared.
#[derive(DeriveIden)]
enum Agreements {
    Table,
    AgreementId,
}
