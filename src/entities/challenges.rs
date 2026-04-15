//! `SeaORM` Entity for challenges table

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "challenges")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub challenge_id: String,
    pub agreement_id: String,
    pub block_height: i64,
    pub challenge_count: i64,
    pub seed: String,
    pub prover_id: String,
    pub deadline_height: i64,
    pub status: String,
    pub proof: Option<String>,
    pub bls_signature: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
