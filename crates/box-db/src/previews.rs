use box_core::{
    AccountContext, BoxId, DomainError, Preview, PreviewAuth, PreviewId, PreviewRepository,
    UtcEpochMillis,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, sea_query::OnConflict,
};

use crate::{DatabaseHandle, internal, parse, scope, text};

mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "previews")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub port: i32,
        pub auth: String,
        pub token_hmac: String,
        pub expires_at: i64,
        pub created_at: i64,
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
pub struct PreviewStore {
    database: DatabaseHandle,
}

impl PreviewStore {
    pub fn new(database: DatabaseHandle) -> Self {
        Self { database }
    }
}

fn active(preview: &Preview) -> entity::ActiveModel {
    entity::ActiveModel {
        id: Set(preview.id.to_string()),
        account_id: Set(preview.account_id.to_string()),
        tenant_id: Set(preview.tenant_id.to_string()),
        box_id: Set(preview.box_id.to_string()),
        port: Set(i32::from(preview.port)),
        auth: Set(text(&preview.auth)),
        token_hmac: Set(preview.token_hmac.clone()),
        expires_at: Set(preview.expires_at.as_millis()),
        created_at: Set(preview.created_at.as_millis()),
        updated_at: Set(preview.updated_at.as_millis()),
    }
}

fn domain(value: entity::Model) -> box_core::Result<Preview> {
    let preview = Preview {
        id: PreviewId::parse(&value.id)?,
        account_id: box_core::AccountId::parse(&value.account_id)?,
        tenant_id: box_core::TenantId::parse(&value.tenant_id)?,
        box_id: BoxId::parse(&value.box_id)?,
        port: u16::try_from(value.port)
            .map_err(|_| DomainError::validation("invalid preview port"))?,
        auth: parse::<PreviewAuth>(&value.auth)?,
        token_hmac: value.token_hmac,
        expires_at: UtcEpochMillis::from_millis(value.expires_at),
        created_at: UtcEpochMillis::from_millis(value.created_at),
        updated_at: UtcEpochMillis::from_millis(value.updated_at),
    };
    preview.validate()?;
    Ok(preview)
}

impl PreviewRepository for PreviewStore {
    async fn create_preview(
        &self,
        context: AccountContext,
        preview: &Preview,
    ) -> box_core::Result<()> {
        if preview.account_id != context.account_id || preview.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        preview.validate()?;
        entity::Entity::insert(active(preview))
            .on_conflict(
                OnConflict::columns([
                    entity::Column::AccountId,
                    entity::Column::TenantId,
                    entity::Column::BoxId,
                    entity::Column::Port,
                ])
                .update_columns([
                    entity::Column::Id,
                    entity::Column::Auth,
                    entity::Column::TokenHmac,
                    entity::Column::ExpiresAt,
                    entity::Column::CreatedAt,
                    entity::Column::UpdatedAt,
                ])
                .to_owned(),
            )
            .exec(self.database.connection())
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn find_preview_by_token_hmac(
        &self,
        token_hmac: &str,
    ) -> box_core::Result<Option<Preview>> {
        entity::Entity::find()
            .filter(entity::Column::TokenHmac.eq(token_hmac))
            .one(self.database.connection())
            .await
            .map_err(internal)?
            .map(domain)
            .transpose()
    }

    async fn list_previews(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<Preview>> {
        let (account, tenant) = scope(context);
        entity::Entity::find()
            .filter(entity::Column::AccountId.eq(account))
            .filter(entity::Column::TenantId.eq(tenant))
            .filter(entity::Column::BoxId.eq(box_id.to_string()))
            .order_by_asc(entity::Column::Port)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }

    async fn delete_preview(
        &self,
        context: AccountContext,
        box_id: BoxId,
        port: u16,
    ) -> box_core::Result<bool> {
        let (account, tenant) = scope(context);
        entity::Entity::delete_many()
            .filter(entity::Column::AccountId.eq(account))
            .filter(entity::Column::TenantId.eq(tenant))
            .filter(entity::Column::BoxId.eq(box_id.to_string()))
            .filter(entity::Column::Port.eq(i32::from(port)))
            .exec(self.database.connection())
            .await
            .map(|result| result.rows_affected > 0)
            .map_err(internal)
    }

    async fn delete_expired_previews(&self, at: UtcEpochMillis) -> box_core::Result<u64> {
        entity::Entity::delete_many()
            .filter(entity::Column::ExpiresAt.lte(at.as_millis()))
            .exec(self.database.connection())
            .await
            .map(|result| result.rows_affected)
            .map_err(internal)
    }
}
