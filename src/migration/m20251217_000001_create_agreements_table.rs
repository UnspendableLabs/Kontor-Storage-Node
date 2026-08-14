use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, boolean, json, string_len, timestamp_with_time_zone},
    sea_orm::{self, sea_query::TableCreateStatement},
};

/// Migration to create the agreements table
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(agreements_table()).await?;

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

/// The `agreements` table, as a statement rather than a call, so the DDL it
/// renders can be asserted against each backend without a database — see the
/// tests below. `up` is the only caller that executes it.
fn agreements_table() -> TableCreateStatement {
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
                .default(json_literal("[]")),
        )
        .col(string_len(Agreements::Root, 128).null())
        .col(big_integer(Agreements::PaddedLen).null())
        .col(boolean(Agreements::Downloaded).not_null().default(false))
        .col(string_len(Agreements::TransactionId, 64).null())
        // The entity declares `pub curation: Json` (non-Option), so the column
        // has to be NOT NULL with a default, and `JsonValue::default()` is
        // `Null` rather than an empty object.
        .col(
            json(Agreements::Curation)
                .not_null()
                .default(json_literal("{}")),
        )
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
        .to_owned()
}

/// A JSON column default, in the one form all three backends accept.
///
/// MySQL refuses a bare literal default on a JSON column outright — *BLOB,
/// TEXT, GEOMETRY or JSON column 'nodes' can't have a default value* — and
/// takes one only as a parenthesised expression, `DEFAULT ('[]')`. Passing a
/// `JsonValue` here would produce `Expr::Value`, which sea-query renders
/// unparenthesised precisely because most defaults are literals; `Expr::cust`
/// falls into the arm that wraps. Postgres coerces the quoted literal to the
/// column type and SQLite accepts any parenthesised expression, so the form
/// that MySQL requires is also valid for the other two.
///
/// `literal` is written into the statement verbatim and must therefore be a
/// SQL string literal — both call sites pass a `&'static str` from this file.
fn json_literal(literal: &'static str) -> Expr {
    Expr::cust(format!("'{literal}'"))
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
    Root,
    PaddedLen,
    Downloaded,
    TransactionId,
    Curation,
    Status,
    CreatedAt,
}

#[cfg(test)]
mod tests {
    use super::agreements_table;
    use sea_orm_migration::sea_orm::sea_query::{
        MysqlQueryBuilder, PostgresQueryBuilder, SqliteQueryBuilder,
    };

    /// The bug this pins: a JSON column default rendered as a bare literal.
    /// MySQL rejects `DEFAULT '[]'` on a JSON column at parse time, so
    /// `migrate up` died on the first table of a schema the README advertises
    /// MySQL for. The parenthesised form is the one MySQL takes, and the CI job
    /// that runs the migrations against real Postgres and MySQL proves the
    /// server agrees; this test is what catches a regression on the two
    /// backends nobody has running locally.
    #[test]
    fn json_defaults_are_parenthesised_on_every_backend() {
        for (backend, ddl) in [
            ("MySQL", agreements_table().to_string(MysqlQueryBuilder)),
            (
                "Postgres",
                agreements_table().to_string(PostgresQueryBuilder),
            ),
            ("SQLite", agreements_table().to_string(SqliteQueryBuilder)),
        ] {
            assert!(
                ddl.contains("DEFAULT ('[]')"),
                "{backend} would take a bare JSON default, which MySQL rejects: {ddl}"
            );
            assert!(
                ddl.contains("DEFAULT ('{}')"),
                "{backend} would take a bare JSON default, which MySQL rejects: {ddl}"
            );
        }
    }

    /// The non-JSON defaults must stay *un*parenthesised on MySQL: 5.7 accepts
    /// no expression defaults at all, and wrapping `CURRENT_TIMESTAMP` would
    /// also stop it being the special form that makes the column auto-populate.
    #[test]
    fn ordinary_defaults_are_left_alone() {
        let ddl = agreements_table().to_string(MysqlQueryBuilder);

        assert!(
            ddl.contains("DEFAULT CURRENT_TIMESTAMP"),
            "the timestamp default should not be wrapped: {ddl}"
        );
        assert!(
            ddl.contains("DEFAULT 'pending'"),
            "the string default should not be wrapped: {ddl}"
        );
    }
}
