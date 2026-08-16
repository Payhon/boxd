use super::{DatabaseHandle, internal};
use box_core::{AccountContext, DomainError};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, SqlErr, TransactionTrait,
    entity::prelude::*, sea_query::Expr,
};

mod entity {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "account_secrets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
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
pub struct AccountSecretRecord {
    pub id: String,
    pub account: AccountContext,
    pub kind: String,
    pub name: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}
impl std::fmt::Debug for AccountSecretRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSecretRecord")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("ciphertext", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}
#[derive(Clone)]
pub struct AccountSecretStore {
    db: DatabaseHandle,
}
impl AccountSecretStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }
    pub async fn put(&self, v: &AccountSecretRecord) -> box_core::Result<()> {
        validate(v)?;
        let a = v.account.account_id.to_string();
        let t = v.account.tenant_id.to_string();
        let ciphertext = hex::encode(&v.ciphertext);
        let nonce = hex::encode(&v.nonce);
        let updated = entity::Entity::update_many()
            .col_expr(entity::Column::Ciphertext, Expr::value(&ciphertext))
            .col_expr(entity::Column::Nonce, Expr::value(&nonce))
            .col_expr(entity::Column::UpdatedAt, Expr::value(v.updated_at))
            .filter(entity::Column::AccountId.eq(&a))
            .filter(entity::Column::TenantId.eq(&t))
            .filter(entity::Column::Kind.eq(&v.kind))
            .filter(entity::Column::Name.eq(&v.name))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        if updated.rows_affected == 1 {
            return Ok(());
        }
        let insert = entity::ActiveModel {
            id: Set(v.id.clone()),
            account_id: Set(a.clone()),
            tenant_id: Set(t.clone()),
            kind: Set(v.kind.clone()),
            name: Set(v.name.clone()),
            ciphertext: Set(ciphertext.clone()),
            nonce: Set(nonce.clone()),
            created_at: Set(v.created_at),
            updated_at: Set(v.updated_at),
        }
        .insert(self.db.connection())
        .await;
        match insert {
            Ok(_) => Ok(()),
            Err(e) if matches!(e.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
                let result = entity::Entity::update_many()
                    .col_expr(entity::Column::Ciphertext, Expr::value(ciphertext))
                    .col_expr(entity::Column::Nonce, Expr::value(nonce))
                    .col_expr(entity::Column::UpdatedAt, Expr::value(v.updated_at))
                    .filter(entity::Column::AccountId.eq(a))
                    .filter(entity::Column::TenantId.eq(t))
                    .filter(entity::Column::Kind.eq(&v.kind))
                    .filter(entity::Column::Name.eq(&v.name))
                    .exec(self.db.connection())
                    .await
                    .map_err(internal)?;
                if result.rows_affected == 1 {
                    Ok(())
                } else {
                    Err(DomainError::state_conflict(
                        "account secret concurrently modified",
                    ))
                }
            }
            Err(e) => Err(internal(e)),
        }
    }
    /// Atomically replaces all secrets within one account/tenant scope.
    pub async fn replace(
        &self,
        context: AccountContext,
        values: &[AccountSecretRecord],
    ) -> box_core::Result<()> {
        for value in values {
            validate(value)?;
            if value.account != context {
                return Err(DomainError::ownership());
            }
        }
        let transaction = self.db.connection().begin().await.map_err(internal)?;
        entity::Entity::delete_many()
            .filter(entity::Column::AccountId.eq(context.account_id.to_string()))
            .filter(entity::Column::TenantId.eq(context.tenant_id.to_string()))
            .exec(&transaction)
            .await
            .map_err(internal)?;
        for value in values {
            entity::ActiveModel {
                id: Set(value.id.clone()),
                account_id: Set(context.account_id.to_string()),
                tenant_id: Set(context.tenant_id.to_string()),
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
    pub async fn list(&self, c: AccountContext) -> box_core::Result<Vec<AccountSecretRecord>> {
        entity::Entity::find()
            .filter(entity::Column::AccountId.eq(c.account_id.to_string()))
            .filter(entity::Column::TenantId.eq(c.tenant_id.to_string()))
            .order_by_asc(entity::Column::Kind)
            .order_by_asc(entity::Column::Name)
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(from_model)
            .collect()
    }
    pub async fn delete(
        &self,
        c: AccountContext,
        kind: &str,
        name: &str,
    ) -> box_core::Result<bool> {
        Ok(entity::Entity::delete_many()
            .filter(entity::Column::AccountId.eq(c.account_id.to_string()))
            .filter(entity::Column::TenantId.eq(c.tenant_id.to_string()))
            .filter(entity::Column::Kind.eq(kind))
            .filter(entity::Column::Name.eq(name))
            .exec(self.db.connection())
            .await
            .map_err(internal)?
            .rows_affected
            == 1)
    }
}
fn validate(v: &AccountSecretRecord) -> box_core::Result<()> {
    if v.id.is_empty()
        || v.kind.is_empty()
        || v.kind.len() > 32
        || v.name.is_empty()
        || v.name.len() > 255
        || v.ciphertext.is_empty()
        || v.nonce.is_empty()
        || v.updated_at < v.created_at
    {
        Err(DomainError::validation(
            "invalid encrypted account secret record",
        ))
    } else {
        Ok(())
    }
}
fn from_model(v: entity::Model) -> box_core::Result<AccountSecretRecord> {
    Ok(AccountSecretRecord {
        id: v.id,
        account: AccountContext {
            account_id: box_core::AccountId::parse(&v.account_id)?,
            tenant_id: box_core::TenantId::parse(&v.tenant_id)?,
        },
        kind: v.kind,
        name: v.name,
        ciphertext: hex::decode(v.ciphertext).map_err(internal)?,
        nonce: hex::decode(v.nonce).map_err(internal)?,
        created_at: v.created_at,
        updated_at: v.updated_at,
    })
}
