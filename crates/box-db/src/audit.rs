use super::{DatabaseHandle, internal};
use box_core::{AccountContext, DomainError};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    entity::prelude::*,
};
use serde_json::Value;

mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "audit_logs")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub actor: String,
        pub action: String,
        pub resource: String,
        pub request_id: Option<String>,
        pub ip: Option<String>,
        pub metadata_json: Option<String>,
        pub created_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuditRecord {
    pub id: String,
    pub context: AccountContext,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub request_id: Option<String>,
    pub ip: Option<String>,
    pub metadata: Value,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct AuditStore {
    db: DatabaseHandle,
}

impl AuditStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    pub async fn append(&self, record: &AuditRecord) -> box_core::Result<()> {
        validate(record)?;
        let metadata_json = serde_json::to_string(&record.metadata).map_err(internal)?;
        entity::ActiveModel {
            id: Set(record.id.clone()),
            account_id: Set(record.context.account_id.to_string()),
            tenant_id: Set(record.context.tenant_id.to_string()),
            actor: Set(record.actor.clone()),
            action: Set(record.action.clone()),
            resource: Set(record.resource.clone()),
            request_id: Set(record.request_id.clone()),
            ip: Set(record.ip.clone()),
            metadata_json: Set(Some(metadata_json)),
            created_at: Set(record.created_at),
        }
        .insert(self.db.connection())
        .await
        .map_err(internal)?;
        Ok(())
    }

    pub async fn list(
        &self,
        context: AccountContext,
        limit: u64,
    ) -> box_core::Result<Vec<AuditRecord>> {
        if limit == 0 || limit > 1_000 {
            return Err(DomainError::validation(
                "audit limit must be between 1 and 1000",
            ));
        }
        entity::Entity::find()
            .filter(entity::Column::AccountId.eq(context.account_id.to_string()))
            .filter(entity::Column::TenantId.eq(context.tenant_id.to_string()))
            .order_by_desc(entity::Column::CreatedAt)
            .order_by_desc(entity::Column::Id)
            .limit(limit)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(from_model)
            .collect()
    }
}

fn validate(record: &AuditRecord) -> box_core::Result<()> {
    if record.id.is_empty()
        || record.actor.is_empty()
        || record.actor.len() > 255
        || record.action.is_empty()
        || record.action.len() > 255
        || record.resource.is_empty()
        || record.resource.len() > 2048
        || record
            .request_id
            .as_ref()
            .is_some_and(|value| value.len() > 255)
        || record.ip.as_ref().is_some_and(|value| value.len() > 255)
        || !record.metadata.is_object()
    {
        return Err(DomainError::validation("invalid audit record"));
    }
    let metadata = serde_json::to_vec(&record.metadata).map_err(internal)?;
    if metadata.len() > 16 * 1024 {
        return Err(DomainError::validation("audit metadata exceeds limit"));
    }
    Ok(())
}

fn from_model(model: entity::Model) -> box_core::Result<AuditRecord> {
    Ok(AuditRecord {
        id: model.id,
        context: AccountContext {
            account_id: box_core::AccountId::parse(&model.account_id)?,
            tenant_id: box_core::TenantId::parse(&model.tenant_id)?,
        },
        actor: model.actor,
        action: model.action,
        resource: model.resource,
        request_id: model.request_id,
        ip: model.ip,
        metadata: model
            .metadata_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(internal)?
            .unwrap_or_else(|| Value::Object(Default::default())),
        created_at: model.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountRecord, AccountStore, connect, migrate};
    use box_core::{AccountId, TenantId, UtcEpochMillis};

    #[tokio::test]
    async fn audit_append_and_list_are_durable_ordered_and_tenant_scoped() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let account_id = AccountId::new();
        AccountStore::new(db.clone())
            .create(&AccountRecord {
                id: account_id,
                name: "audit-fixture".into(),
                status: "active".into(),
                created_at: UtcEpochMillis::from_millis(1),
                updated_at: UtcEpochMillis::from_millis(1),
            })
            .await
            .unwrap();
        let first = AccountContext {
            account_id,
            tenant_id: TenantId::new(),
        };
        let second = AccountContext {
            account_id,
            tenant_id: TenantId::new(),
        };
        let store = AuditStore::new(db);
        for (id, context, created_at) in [("a", first, 10), ("b", first, 20), ("c", second, 30)] {
            store
                .append(&AuditRecord {
                    id: id.into(),
                    context,
                    actor: "compat_api_key".into(),
                    action: "POST /v2/box".into(),
                    resource: "/v2/box".into(),
                    request_id: Some(format!("request-{id}")),
                    ip: Some("127.0.0.1".into()),
                    metadata: serde_json::json!({"status_code":200,"succeeded":true}),
                    created_at,
                })
                .await
                .unwrap();
        }
        let records = store.list(first, 10).await.unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            ["b", "a"]
        );
        assert!(records.iter().all(|record| record.context == first));
        assert_eq!(store.list(second, 10).await.unwrap().len(), 1);
        assert!(store.list(first, 0).await.is_err());
    }
}
