//! `SeaORM` Entity for the `node_state` table: the few facts the daemon has
//! to carry across a restart that belong to no agreement or challenge.
//!
//! One row per fact, keyed by name, with the value as text. The first is the
//! start of the stake withdrawal delay (`stake::WITHDRAWAL_STARTED_AT`): the
//! node times Kontor's 2028-block delay from when it first saw the withdrawal
//! height, and timing it from process start instead meant every restart put
//! the two weeks back on the clock.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "node_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    pub value: String,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
