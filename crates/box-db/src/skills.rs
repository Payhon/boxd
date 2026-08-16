use box_core::{
    AccountContext, BoxId, DomainError, EnabledSkill, SkillRepository, UtcEpochMillis,
    validate_skill_id,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, sea_query::OnConflict,
};
use uuid::Uuid;

use crate::{DatabaseHandle, internal, scope};

mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "box_skills")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub skill_id: String,
        pub name: String,
        pub source_commit: String,
        pub content_sha256: String,
        pub created_at: i64,
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
pub struct SkillStore {
    database: DatabaseHandle,
}

impl SkillStore {
    pub fn new(database: DatabaseHandle) -> Self {
        Self { database }
    }
}

fn domain(value: entity::Model) -> box_core::Result<EnabledSkill> {
    let expected_name = validate_skill_id(&value.skill_id)?;
    if expected_name != value.name {
        return Err(DomainError::validation("stored skill name mismatch"));
    }
    Ok(EnabledSkill {
        account_id: box_core::AccountId::parse(&value.account_id)?,
        tenant_id: box_core::TenantId::parse(&value.tenant_id)?,
        box_id: BoxId::parse(&value.box_id)?,
        skill_id: value.skill_id,
        name: value.name,
        source_commit: value.source_commit,
        content_sha256: value.content_sha256,
        created_at: UtcEpochMillis::from_millis(value.created_at),
        updated_at: UtcEpochMillis::from_millis(value.updated_at),
    })
}

impl SkillRepository for SkillStore {
    async fn upsert_skill(
        &self,
        context: AccountContext,
        skill: &EnabledSkill,
    ) -> box_core::Result<()> {
        if skill.account_id != context.account_id || skill.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        if validate_skill_id(&skill.skill_id)? != skill.name {
            return Err(DomainError::validation("skill name mismatch"));
        }
        entity::Entity::insert(entity::ActiveModel {
            id: Set(Uuid::now_v7().to_string()),
            account_id: Set(context.account_id.to_string()),
            tenant_id: Set(context.tenant_id.to_string()),
            box_id: Set(skill.box_id.to_string()),
            skill_id: Set(skill.skill_id.clone()),
            name: Set(skill.name.clone()),
            source_commit: Set(skill.source_commit.clone()),
            content_sha256: Set(skill.content_sha256.clone()),
            created_at: Set(skill.created_at.as_millis()),
            updated_at: Set(skill.updated_at.as_millis()),
        })
        .on_conflict(
            OnConflict::columns([
                entity::Column::AccountId,
                entity::Column::TenantId,
                entity::Column::BoxId,
                entity::Column::SkillId,
            ])
            .update_columns([
                entity::Column::Name,
                entity::Column::SourceCommit,
                entity::Column::ContentSha256,
                entity::Column::UpdatedAt,
            ])
            .to_owned(),
        )
        .exec(self.database.connection())
        .await
        .map(|_| ())
        .map_err(internal)
    }

    async fn list_skills(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<EnabledSkill>> {
        let (account, tenant) = scope(context);
        entity::Entity::find()
            .filter(entity::Column::AccountId.eq(account))
            .filter(entity::Column::TenantId.eq(tenant))
            .filter(entity::Column::BoxId.eq(box_id.to_string()))
            .order_by_asc(entity::Column::SkillId)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }

    async fn delete_skill(
        &self,
        context: AccountContext,
        box_id: BoxId,
        skill_id: &str,
    ) -> box_core::Result<bool> {
        validate_skill_id(skill_id)?;
        let (account, tenant) = scope(context);
        entity::Entity::delete_many()
            .filter(entity::Column::AccountId.eq(account))
            .filter(entity::Column::TenantId.eq(tenant))
            .filter(entity::Column::BoxId.eq(box_id.to_string()))
            .filter(entity::Column::SkillId.eq(skill_id))
            .exec(self.database.connection())
            .await
            .map(|result| result.rows_affected > 0)
            .map_err(internal)
    }
}
