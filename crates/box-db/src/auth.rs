use std::{collections::BTreeSet, fmt};

use box_core::{AccountContext, AuthScope, DomainError, TenantId};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, SqlErr,
    TransactionTrait, entity::prelude::*, sea_query::Expr,
};

use super::{DatabaseHandle, internal, text};

mod users {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub username: String,
        pub password_hash: String,
        pub role: String,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod admin_sessions {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "admin_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub user_id: String,
        pub token_prefix: String,
        pub token_hmac: String,
        pub csrf_hmac: String,
        pub expires_at: i64,
        pub revoked_at: Option<i64>,
        pub last_seen_at: Option<i64>,
        pub created_at: i64,
        pub updated_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod bootstrap_state {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "bootstrap_state")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub completed_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub id: String,
    pub account: AccountContext,
    pub username: String,
    password_hash: String,
    pub role: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl UserRecord {
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserRecord")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("role", &self.role)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct UserStore {
    db: DatabaseHandle,
}

impl UserStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    pub async fn find_by_username(
        &self,
        account: AccountContext,
        username: &str,
    ) -> box_core::Result<Option<UserRecord>> {
        users::Entity::find()
            .filter(users::Column::AccountId.eq(account.account_id.to_string()))
            .filter(users::Column::TenantId.eq(account.tenant_id.to_string()))
            .filter(users::Column::Username.eq(username))
            .one(self.db.connection())
            .await
            .map_err(internal)?
            .map(user_from_model)
            .transpose()
    }

    /// Returns the local administrator only when the username is globally
    /// unambiguous. Ambiguity is intentionally indistinguishable from absence.
    pub async fn find_unique_local_admin(
        &self,
        username: &str,
    ) -> box_core::Result<Option<UserRecord>> {
        let mut candidates = users::Entity::find()
            .filter(users::Column::Username.eq(username))
            .filter(users::Column::Role.eq("admin"))
            .limit(2)
            .all(self.db.connection())
            .await
            .map_err(internal)?;
        if candidates.len() != 1 {
            return Ok(None);
        }
        candidates.pop().map(user_from_model).transpose()
    }

    pub async fn account_contexts(&self) -> box_core::Result<Vec<AccountContext>> {
        let mut values = Vec::new();
        for model in users::Entity::find()
            .all(self.db.connection())
            .await
            .map_err(internal)?
        {
            let context = AccountContext {
                account_id: box_core::AccountId::parse(&model.account_id)?,
                tenant_id: TenantId::parse(&model.tenant_id)?,
            };
            if !values.contains(&context) {
                values.push(context);
            }
        }
        Ok(values)
    }
}

fn user_from_model(model: users::Model) -> box_core::Result<UserRecord> {
    Ok(UserRecord {
        id: model.id,
        account: AccountContext {
            account_id: box_core::AccountId::parse(&model.account_id)?,
            tenant_id: TenantId::parse(&model.tenant_id)?,
        },
        username: model.username,
        password_hash: model.password_hash,
        role: model.role,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionInsert {
    pub id: String,
    pub account: AccountContext,
    pub user_id: String,
    pub token_prefix: String,
    pub token_hmac: String,
    pub csrf_hmac: String,
    pub expires_at: i64,
    pub created_at: i64,
}

impl fmt::Debug for SessionInsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionInsert")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("user_id", &self.user_id)
            .field("token_prefix", &self.token_prefix)
            .field("token_hmac", &"[REDACTED]")
            .field("csrf_hmac", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionCandidate {
    pub id: String,
    pub account: AccountContext,
    pub user_id: String,
    pub token_hmac: String,
    pub csrf_hmac: String,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

impl fmt::Debug for SessionCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCandidate")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("user_id", &self.user_id)
            .field("token_hmac", &"[REDACTED]")
            .field("csrf_hmac", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct AdminSessionStore {
    db: DatabaseHandle,
}

impl AdminSessionStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    pub async fn insert(&self, value: &SessionInsert) -> box_core::Result<()> {
        if value.id.is_empty()
            || value.user_id.is_empty()
            || value.token_prefix.is_empty()
            || value.token_hmac.len() != 64
            || value.csrf_hmac.len() != 64
            || value.expires_at <= value.created_at
        {
            return Err(DomainError::validation("invalid admin session record"));
        }
        admin_sessions::ActiveModel {
            id: Set(value.id.clone()),
            account_id: Set(value.account.account_id.to_string()),
            tenant_id: Set(value.account.tenant_id.to_string()),
            user_id: Set(value.user_id.clone()),
            token_prefix: Set(value.token_prefix.clone()),
            token_hmac: Set(value.token_hmac.clone()),
            csrf_hmac: Set(value.csrf_hmac.clone()),
            expires_at: Set(value.expires_at),
            revoked_at: Set(None),
            last_seen_at: Set(None),
            created_at: Set(value.created_at),
            updated_at: Set(value.created_at),
        }
        .insert(self.db.connection())
        .await
        .map_err(internal)?;
        Ok(())
    }

    pub async fn candidates(&self, prefix: &str) -> box_core::Result<Vec<SessionCandidate>> {
        admin_sessions::Entity::find()
            .filter(admin_sessions::Column::TokenPrefix.eq(prefix))
            .all(self.db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(|model| {
                Ok(SessionCandidate {
                    id: model.id,
                    account: AccountContext {
                        account_id: box_core::AccountId::parse(&model.account_id)?,
                        tenant_id: TenantId::parse(&model.tenant_id)?,
                    },
                    user_id: model.user_id,
                    token_hmac: model.token_hmac,
                    csrf_hmac: model.csrf_hmac,
                    expires_at: model.expires_at,
                    revoked_at: model.revoked_at,
                })
            })
            .collect()
    }

    pub async fn touch_if_active(
        &self,
        candidate: &SessionCandidate,
        timestamp: i64,
    ) -> box_core::Result<bool> {
        let result = admin_sessions::Entity::update_many()
            .col_expr(
                admin_sessions::Column::LastSeenAt,
                Expr::value(Some(timestamp)),
            )
            .col_expr(admin_sessions::Column::UpdatedAt, Expr::value(timestamp))
            .filter(admin_sessions::Column::Id.eq(&candidate.id))
            .filter(admin_sessions::Column::AccountId.eq(candidate.account.account_id.to_string()))
            .filter(admin_sessions::Column::TenantId.eq(candidate.account.tenant_id.to_string()))
            .filter(admin_sessions::Column::UserId.eq(&candidate.user_id))
            .filter(admin_sessions::Column::RevokedAt.is_null())
            .filter(admin_sessions::Column::ExpiresAt.gt(timestamp))
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(result.rows_affected == 1)
    }

    pub async fn revoke(
        &self,
        account: AccountContext,
        session_id: &str,
        timestamp: i64,
    ) -> box_core::Result<bool> {
        let result = admin_sessions::Entity::update_many()
            .col_expr(
                admin_sessions::Column::RevokedAt,
                Expr::value(Some(timestamp)),
            )
            .col_expr(admin_sessions::Column::UpdatedAt, Expr::value(timestamp))
            .filter(admin_sessions::Column::Id.eq(session_id))
            .filter(admin_sessions::Column::AccountId.eq(account.account_id.to_string()))
            .filter(admin_sessions::Column::TenantId.eq(account.tenant_id.to_string()))
            .filter(admin_sessions::Column::RevokedAt.is_null())
            .exec(self.db.connection())
            .await
            .map_err(internal)?;
        Ok(result.rows_affected == 1)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapSeed {
    pub account: AccountContext,
    pub account_name: String,
    pub user_id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub api_key_id: String,
    pub api_key_prefix: String,
    pub api_key_hmac: String,
    pub api_key_scopes: BTreeSet<AuthScope>,
    pub created_at: i64,
}

impl fmt::Debug for BootstrapSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapSeed")
            .field("account", &self.account)
            .field("account_name", &self.account_name)
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("role", &self.role)
            .field("api_key_id", &self.api_key_id)
            .field("api_key_prefix", &self.api_key_prefix)
            .field("api_key_hmac", &"[REDACTED]")
            .field("api_key_scopes", &self.api_key_scopes)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct BootstrapStore {
    db: DatabaseHandle,
}

impl BootstrapStore {
    pub fn new(db: DatabaseHandle) -> Self {
        Self { db }
    }

    pub async fn initialize(&self, seed: &BootstrapSeed) -> box_core::Result<()> {
        validate_bootstrap(seed)?;
        let transaction = self.db.begin().await.map_err(internal)?;
        let account_count = super::accounts::Entity::find()
            .count(&transaction)
            .await
            .map_err(internal)?;
        let user_count = users::Entity::find()
            .count(&transaction)
            .await
            .map_err(internal)?;
        let state_count = bootstrap_state::Entity::find()
            .count(&transaction)
            .await
            .map_err(internal)?;
        if account_count != 0 || user_count != 0 || state_count != 0 {
            return Err(DomainError::state_conflict(
                "database bootstrap has already been completed or database is not empty",
            ));
        }

        bootstrap_state::ActiveModel {
            id: Set("singleton".to_owned()),
            completed_at: Set(seed.created_at),
        }
        .insert(&transaction)
        .await
        .map_err(bootstrap_insert_error)?;
        super::accounts::ActiveModel {
            id: Set(seed.account.account_id.to_string()),
            name: Set(seed.account_name.clone()),
            status: Set("active".to_owned()),
            created_at: Set(seed.created_at),
            updated_at: Set(seed.created_at),
        }
        .insert(&transaction)
        .await
        .map_err(bootstrap_insert_error)?;
        users::ActiveModel {
            id: Set(seed.user_id.clone()),
            account_id: Set(seed.account.account_id.to_string()),
            tenant_id: Set(seed.account.tenant_id.to_string()),
            username: Set(seed.username.clone()),
            password_hash: Set(seed.password_hash.clone()),
            role: Set(seed.role.clone()),
            created_at: Set(seed.created_at),
            updated_at: Set(seed.created_at),
        }
        .insert(&transaction)
        .await
        .map_err(bootstrap_insert_error)?;
        super::api_keys::ActiveModel {
            id: Set(seed.api_key_id.clone()),
            account_id: Set(seed.account.account_id.to_string()),
            tenant_id: Set(seed.account.tenant_id.to_string()),
            prefix: Set(seed.api_key_prefix.clone()),
            key_hmac: Set(seed.api_key_hmac.clone()),
            scopes_json: Set(text(&seed.api_key_scopes)),
            last_used_at: Set(None),
            expires_at: Set(None),
            created_at: Set(seed.created_at),
            updated_at: Set(seed.created_at),
        }
        .insert(&transaction)
        .await
        .map_err(bootstrap_insert_error)?;
        transaction.commit().await.map_err(internal)
    }
}

fn validate_bootstrap(seed: &BootstrapSeed) -> box_core::Result<()> {
    if seed.account_name.trim().is_empty()
        || seed.username.trim().is_empty()
        || seed.user_id.is_empty()
        || seed.password_hash.is_empty()
        || seed.role != "admin"
        || seed.api_key_id.is_empty()
        || seed.api_key_prefix.is_empty()
        || seed.api_key_hmac.len() != 64
        || seed.api_key_scopes.contains(&AuthScope::Admin)
    {
        return Err(DomainError::validation("invalid bootstrap record"));
    }
    Ok(())
}

fn bootstrap_insert_error(error: DbErr) -> DomainError {
    if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        DomainError::state_conflict("database bootstrap has already been completed")
    } else {
        internal(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connect, migrate};
    use box_core::{AccountId, TenantId};

    fn context() -> AccountContext {
        AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        }
    }

    fn seed(account: AccountContext) -> BootstrapSeed {
        BootstrapSeed {
            account,
            account_name: "local".to_owned(),
            user_id: uuid::Uuid::now_v7().to_string(),
            username: "admin".to_owned(),
            password_hash: "$argon2id$redacted".to_owned(),
            role: "admin".to_owned(),
            api_key_id: uuid::Uuid::now_v7().to_string(),
            api_key_prefix: "boxd_compat_12345678".to_owned(),
            api_key_hmac: "ab".repeat(32),
            api_key_scopes: BTreeSet::from([AuthScope::BoxesRead]),
            created_at: crate::now(),
        }
    }

    #[tokio::test]
    async fn bootstrap_is_atomic_one_time_and_records_are_redacted() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let store = BootstrapStore::new(db.clone());
        let value = seed(context());
        let debug = format!("{value:?}");
        assert!(!debug.contains(&value.password_hash));
        assert!(!debug.contains(&value.api_key_hmac));
        store.initialize(&value).await.unwrap();
        assert_eq!(
            store.initialize(&seed(context())).await.unwrap_err().code,
            "state_conflict"
        );
        let user = UserStore::new(db)
            .find_by_username(value.account, "admin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.account, value.account);
        assert!(!format!("{user:?}").contains(user.password_hash()));
    }

    #[tokio::test]
    async fn session_foreign_key_enforces_tenant_owner() {
        let db = connect("sqlite::memory:", 1).await.unwrap();
        migrate(&db).await.unwrap();
        let value = seed(context());
        BootstrapStore::new(db.clone())
            .initialize(&value)
            .await
            .unwrap();
        let wrong_tenant = AccountContext {
            account_id: value.account.account_id,
            tenant_id: TenantId::new(),
        };
        let error = AdminSessionStore::new(db)
            .insert(&SessionInsert {
                id: uuid::Uuid::now_v7().to_string(),
                account: wrong_tenant,
                user_id: value.user_id,
                token_prefix: "prefix".to_owned(),
                token_hmac: "11".repeat(32),
                csrf_hmac: "22".repeat(32),
                expires_at: value.created_at + 10_000,
                created_at: value.created_at,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "database_error");
    }
}
