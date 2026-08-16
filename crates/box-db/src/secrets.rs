use std::fmt;

use box_core::{AccountContext, BoxId, DomainError, TenantId};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, SqlErr, TransactionTrait,
    entity::prelude::*, sea_query::Expr,
};

use super::{DatabaseHandle, internal};

mod box_secrets {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "box_secrets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub kind: String,
        pub name: String,
        pub ciphertext: String,
        pub nonce: String,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretRecord {
    pub id: String,
    pub account: AccountContext,
    pub box_id: BoxId,
    pub kind: String,
    pub name: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRecord")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("box_id", &self.box_id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("ciphertext", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct SecretStore {
    db: DatabaseHandle,
}

impl SecretStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    /// Inserts or replaces exactly one secret within its account/tenant/box scope.
    pub async fn put(&self, value: &SecretRecord) -> box_core::Result<()> {
        validate(value)?;
        let account_id = value.account.account_id.to_string();
        let tenant_id = value.account.tenant_id.to_string();
        let box_id = value.box_id.to_string();
        let ciphertext = hex::encode(&value.ciphertext);
        let nonce = hex::encode(&value.nonce);
        let update = box_secrets::Entity::update_many()
            .col_expr(box_secrets::Column::Ciphertext, Expr::value(&ciphertext))
            .col_expr(box_secrets::Column::Nonce, Expr::value(&nonce))
            .col_expr(
                box_secrets::Column::UpdatedAt,
                Expr::value(value.updated_at),
            )
            .filter(box_secrets::Column::AccountId.eq(&account_id))
            .filter(box_secrets::Column::TenantId.eq(&tenant_id))
            .filter(box_secrets::Column::BoxId.eq(&box_id))
            .filter(box_secrets::Column::Kind.eq(&value.kind))
            .filter(box_secrets::Column::Name.eq(&value.name))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if update.rows_affected == 1 {
            return Ok(());
        }
        let inserted = box_secrets::ActiveModel {
            id: Set(value.id.clone()),
            account_id: Set(account_id.clone()),
            tenant_id: Set(tenant_id.clone()),
            box_id: Set(box_id.clone()),
            kind: Set(value.kind.clone()),
            name: Set(value.name.clone()),
            ciphertext: Set(ciphertext.clone()),
            nonce: Set(nonce.clone()),
            created_at: Set(value.created_at),
            updated_at: Set(value.updated_at),
        }
        .insert(self.db.connection())
        .await;
        match inserted {
            Ok(_) => Ok(()),
            Err(error) if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
                // A concurrent writer won the unique scope key. Update that row
                // without ever falling back to an unscoped identifier lookup.
                let retry = box_secrets::Entity::update_many()
                    .col_expr(box_secrets::Column::Ciphertext, Expr::value(ciphertext))
                    .col_expr(box_secrets::Column::Nonce, Expr::value(nonce))
                    .col_expr(
                        box_secrets::Column::UpdatedAt,
                        Expr::value(value.updated_at),
                    )
                    .filter(box_secrets::Column::AccountId.eq(account_id))
                    .filter(box_secrets::Column::TenantId.eq(tenant_id))
                    .filter(box_secrets::Column::BoxId.eq(box_id))
                    .filter(box_secrets::Column::Kind.eq(&value.kind))
                    .filter(box_secrets::Column::Name.eq(&value.name))
                    .exec(self.db.connection())
                    .await
                    .map_err(internal)?;
                if retry.rows_affected == 1 {
                    Ok(())
                } else {
                    Err(DomainError::state_conflict(
                        "secret was concurrently modified",
                    ))
                }
            }
            Err(error) => Err(internal(error)),
        }
    }

    /// Atomically replaces environment secrets for one account/tenant/box
    /// scope without deleting other kinds such as the durable init command.
    pub async fn replace(
        &self,
        account: AccountContext,
        box_id: BoxId,
        values: &[SecretRecord],
    ) -> box_core::Result<()> {
        for value in values {
            validate(value)?;
            if value.account != account || value.box_id != box_id || value.kind != "env" {
                return Err(DomainError::ownership());
            }
        }
        let transaction = self.db.connection().begin().await.map_err(internal)?;
        box_secrets::Entity::delete_many()
            .filter(box_secrets::Column::AccountId.eq(account.account_id.to_string()))
            .filter(box_secrets::Column::TenantId.eq(account.tenant_id.to_string()))
            .filter(box_secrets::Column::BoxId.eq(box_id.to_string()))
            .filter(box_secrets::Column::Kind.eq("env"))
            .exec(&transaction)
            .await
            .map_err(internal)?;
        for value in values {
            box_secrets::ActiveModel {
                id: Set(value.id.clone()),
                account_id: Set(account.account_id.to_string()),
                tenant_id: Set(account.tenant_id.to_string()),
                box_id: Set(box_id.to_string()),
                kind: Set(value.kind.clone()),
                name: Set(value.name.clone()),
                ciphertext: Set(hex::encode(&value.ciphertext)),
                nonce: Set(hex::encode(&value.nonce)),
                created_at: Set(value.created_at),
                updated_at: Set(value.updated_at),
            }
            .insert(&transaction)
            .await
            .map_err(internal)?;
        }
        transaction.commit().await.map_err(internal)
    }

    pub async fn get(
        &self,
        account: AccountContext,
        box_id: BoxId,
        kind: &str,
        name: &str,
    ) -> box_core::Result<Option<SecretRecord>> {
        box_secrets::Entity::find()
            .filter(box_secrets::Column::AccountId.eq(account.account_id.to_string()))
            .filter(box_secrets::Column::TenantId.eq(account.tenant_id.to_string()))
            .filter(box_secrets::Column::BoxId.eq(box_id.to_string()))
            .filter(box_secrets::Column::Kind.eq(kind))
            .filter(box_secrets::Column::Name.eq(name))
            .one(self.db.connection())
            .await
            .map_err(internal)?
            .map(from_model)
            .transpose()
    }

    pub async fn list(
        &self,
        account: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Vec<SecretRecord>> {
        box_secrets::Entity::find()
            .filter(box_secrets::Column::AccountId.eq(account.account_id.to_string()))
            .filter(box_secrets::Column::TenantId.eq(account.tenant_id.to_string()))
            .filter(box_secrets::Column::BoxId.eq(box_id.to_string()))
            .order_by_asc(box_secrets::Column::Kind)
            .order_by_asc(box_secrets::Column::Name)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(from_model)
            .collect()
    }

    pub async fn delete(
        &self,
        account: AccountContext,
        box_id: BoxId,
        kind: &str,
        name: &str,
    ) -> box_core::Result<bool> {
        let result = box_secrets::Entity::delete_many()
            .filter(box_secrets::Column::AccountId.eq(account.account_id.to_string()))
            .filter(box_secrets::Column::TenantId.eq(account.tenant_id.to_string()))
            .filter(box_secrets::Column::BoxId.eq(box_id.to_string()))
            .filter(box_secrets::Column::Kind.eq(kind))
            .filter(box_secrets::Column::Name.eq(name))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(result.rows_affected == 1)
    }
}

fn validate(value: &SecretRecord) -> box_core::Result<()> {
    if value.id.is_empty()
        || value.kind.is_empty()
        || value.kind.len() > 32
        || value.name.is_empty()
        || value.name.len() > 255
        || value.ciphertext.is_empty()
        || value.nonce.is_empty()
        || value.updated_at < value.created_at
    {
        return Err(DomainError::validation("invalid encrypted secret record"));
    }
    Ok(())
}

fn from_model(model: box_secrets::Model) -> box_core::Result<SecretRecord> {
    Ok(SecretRecord {
        id: model.id,
        account: AccountContext {
            account_id: box_core::AccountId::parse(&model.account_id)?,
            tenant_id: TenantId::parse(&model.tenant_id)?,
        },
        box_id: BoxId::parse(&model.box_id)?,
        kind: model.kind,
        name: model.name,
        ciphertext: hex::decode(model.ciphertext).map_err(internal)?,
        nonce: hex::decode(model.nonce).map_err(internal)?,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountRecord, AccountStore, SeaRepository, connect, migrate};
    use box_core::{
        AccountId, Box as DomainBox, BoxCreateSpec, BoxRepository, BoxSize, NetworkPolicy, Runtime,
        UtcEpochMillis,
    };

    async fn seed_box(db: &DatabaseHandle) -> (AccountContext, BoxId) {
        let account = AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        };
        AccountStore::new(db.clone())
            .create(&AccountRecord {
                id: account.account_id,
                name: "secret-test".to_owned(),
                status: "active".to_owned(),
                created_at: UtcEpochMillis::from_millis(1),
                updated_at: UtcEpochMillis::from_millis(1),
            })
            .await
            .unwrap();
        let value = DomainBox::new(
            account,
            BoxCreateSpec {
                name: None,
                labels: vec![],
                runtime: Runtime::Node,
                size: BoxSize::Small,
                browser: false,
                keep_alive: false,
                ephemeral: None,
                attach_headers_requested: false,
                network_policy: NetworkPolicy::DenyAll,
            },
            UtcEpochMillis::from_millis(1),
        )
        .unwrap();
        BoxRepository::create(&SeaRepository::new(db.clone()), account, &value)
            .await
            .unwrap();
        (account, value.id)
    }

    #[tokio::test]
    async fn ciphertext_roundtrip_upsert_and_tenant_isolation() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let (account, box_id) = seed_box(&db).await;
        let store = SecretStore::new(db);
        let mut record = SecretRecord {
            id: uuid::Uuid::now_v7().to_string(),
            account,
            box_id,
            kind: "env".to_owned(),
            name: "TOKEN".to_owned(),
            ciphertext: vec![0, 1, 2, 254, 255],
            nonce: vec![9; 24],
            created_at: 1,
            updated_at: 1,
        };
        store.put(&record).await.unwrap();
        assert_eq!(
            store.get(account, box_id, "env", "TOKEN").await.unwrap(),
            Some(record.clone())
        );
        record.id = uuid::Uuid::now_v7().to_string();
        record.ciphertext = vec![7, 8, 9];
        record.updated_at = 2;
        store.put(&record).await.unwrap();
        let loaded = store
            .get(account, box_id, "env", "TOKEN")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.ciphertext, record.ciphertext);
        assert_eq!(loaded.updated_at, 2);
        assert_eq!(store.list(account, box_id).await.unwrap().len(), 1);

        let replacement = SecretRecord {
            id: uuid::Uuid::now_v7().to_string(),
            account,
            box_id,
            kind: "env".to_owned(),
            name: "NEXT".to_owned(),
            ciphertext: vec![4, 5, 6],
            nonce: vec![8; 24],
            created_at: 3,
            updated_at: 3,
        };
        let init = SecretRecord {
            id: uuid::Uuid::now_v7().to_string(),
            account,
            box_id,
            kind: "init_command".to_owned(),
            name: "command".to_owned(),
            ciphertext: vec![6, 6, 6],
            nonce: vec![7; 24],
            created_at: 3,
            updated_at: 3,
        };
        store.put(&init).await.unwrap();
        let mut wrong_scope = replacement.clone();
        wrong_scope.account.tenant_id = TenantId::new();
        assert!(
            store
                .replace(account, box_id, &[replacement.clone(), wrong_scope])
                .await
                .is_err()
        );
        assert!(
            store
                .get(account, box_id, "env", "TOKEN")
                .await
                .unwrap()
                .is_some()
        );
        store
            .replace(account, box_id, std::slice::from_ref(&replacement))
            .await
            .unwrap();
        assert!(
            store
                .get(account, box_id, "env", "TOKEN")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get(account, box_id, "init_command", "command")
                .await
                .unwrap(),
            Some(init)
        );
        assert!(
            store
                .get(account, box_id, "env", "NEXT")
                .await
                .unwrap()
                .is_some()
        );

        let other_tenant = AccountContext {
            account_id: account.account_id,
            tenant_id: TenantId::new(),
        };
        assert!(
            store
                .get(other_tenant, box_id, "env", "TOKEN")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .delete(other_tenant, box_id, "env", "TOKEN")
                .await
                .unwrap()
        );
        assert!(store.delete(account, box_id, "env", "NEXT").await.unwrap());
        assert!(!store.delete(account, box_id, "env", "NEXT").await.unwrap());
    }
}
