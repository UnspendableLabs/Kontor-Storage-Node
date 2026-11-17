//! Creates `node_state`: a key/value table for the facts the daemon must keep
//! across restarts that belong to no agreement or challenge.
//!
//! The first of them is when the node first saw its stake's withdrawal height.
//! Kontor only accepts `withdraw-stake` 2028 blocks after `begin-unstake`, and
//! the node — which cannot see the chain tip — times that delay itself from
//! the moment it first saw the height. Kept in memory, the moment moved to
//! process start on every restart, and an operator who restarted the node
//! mid-exit waited the two weeks again.
use sea_orm_migration::{
    prelude::{DbErr, DeriveIden, DeriveMigrationName, MigrationTrait, SchemaManager, Table},
    schema::{string_len, text, timestamp_with_time_zone},
    sea_orm,
};

/// Migration creating the `node_state` table.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(NodeState::Table)
                    .if_not_exists()
                    .col(string_len(NodeState::Key, 64).primary_key())
                    .col(text(NodeState::Value).not_null())
                    .col(timestamp_with_time_zone(NodeState::UpdatedAt).not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(NodeState::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum NodeState {
    Table,
    Key,
    Value,
    UpdatedAt,
}
