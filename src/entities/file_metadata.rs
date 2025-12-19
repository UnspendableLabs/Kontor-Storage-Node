//! `SeaORM` Entity for file metadata persistence.

use sea_orm::entity::prelude::*;
use sea_orm::sea_query::Expr;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "file_metadata")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub agreement_id: String,
    pub filename: String,
    pub root: String,
    pub file_id: String,
    pub original_size: i64,
    pub padded_len: i64,
    #[sea_orm(
        column_type = "TimestampWithTimeZone",
        default_expr = "Expr::current_timestamp()"
    )]
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::agreements::Entity",
        from = "Column::AgreementId",
        to = "super::agreements::Column::AgreementId",
        on_delete = "Cascade"
    )]
    Agreements,
}

impl Related<super::agreements::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Agreements.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
