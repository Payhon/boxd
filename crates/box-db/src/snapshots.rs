use box_core::{
    AccountContext, BoxId, DomainError, Snapshot, SnapshotId, SnapshotRepository, SnapshotStatus,
    UtcEpochMillis,
};
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{DatabaseHandle, internal, parse, scope, text};

mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "snapshots")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub name: String,
        pub status: String,
        pub disk_path: Option<String>,
        pub size_bytes: i64,
        pub checksum: Option<String>,
        pub created_at: i64,
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
pub struct SnapshotStore {
    database: DatabaseHandle,
}

impl SnapshotStore {
    pub fn new(database: DatabaseHandle) -> Self {
        Self { database }
    }

    pub async fn list_all(&self) -> box_core::Result<Vec<Snapshot>> {
        entity::Entity::find()
            .order_by_asc(entity::Column::CreatedAt)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }
}

fn model(snapshot: &Snapshot) -> box_core::Result<entity::ActiveModel> {
    Ok(entity::ActiveModel {
        id: Set(snapshot.id.to_string()),
        account_id: Set(snapshot.account_id.to_string()),
        tenant_id: Set(snapshot.tenant_id.to_string()),
        box_id: Set(snapshot.box_id.to_string()),
        name: Set(snapshot.name.clone()),
        status: Set(text(&snapshot.status)),
        disk_path: Set(snapshot.disk_path.clone()),
        size_bytes: Set(i64::try_from(snapshot.size_bytes)
            .map_err(|_| DomainError::validation("snapshot size is too large"))?),
        checksum: Set(snapshot.checksum.clone()),
        created_at: Set(snapshot.created_at.as_millis()),
        updated_at: Set(snapshot.updated_at.as_millis()),
    })
}

fn domain(value: entity::Model) -> box_core::Result<Snapshot> {
    Ok(Snapshot {
        id: SnapshotId::parse(&value.id)?,
        account_id: box_core::AccountId::parse(&value.account_id)?,
        tenant_id: box_core::TenantId::parse(&value.tenant_id)?,
        box_id: BoxId::parse(&value.box_id)?,
        name: value.name,
        status: parse::<SnapshotStatus>(&value.status)?,
        disk_path: value.disk_path,
        size_bytes: u64::try_from(value.size_bytes).map_err(internal)?,
        checksum: value.checksum,
        created_at: UtcEpochMillis::from_millis(value.created_at),
        updated_at: UtcEpochMillis::from_millis(value.updated_at),
    })
}

fn scoped(context: AccountContext) -> sea_orm::Select<entity::Entity> {
    let (account, tenant) = scope(context);
    entity::Entity::find()
        .filter(entity::Column::AccountId.eq(account))
        .filter(entity::Column::TenantId.eq(tenant))
}

impl SnapshotRepository for SnapshotStore {
    async fn create_snapshot(
        &self,
        context: AccountContext,
        snapshot: &Snapshot,
    ) -> box_core::Result<()> {
        if snapshot.account_id != context.account_id || snapshot.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        entity::Entity::insert(model(snapshot)?)
            .exec(self.database.connection())
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn find_snapshot(
        &self,
        context: AccountContext,
        id: SnapshotId,
    ) -> box_core::Result<Option<Snapshot>> {
        scoped(context)
            .filter(entity::Column::Id.eq(id.to_string()))
            .one(self.database.connection())
            .await
            .map_err(internal)?
            .map(domain)
            .transpose()
    }

    async fn list_snapshots(
        &self,
        context: AccountContext,
        box_id: Option<BoxId>,
    ) -> box_core::Result<Vec<Snapshot>> {
        let mut query = scoped(context);
        if let Some(box_id) = box_id {
            query = query.filter(entity::Column::BoxId.eq(box_id.to_string()));
        }
        query
            .order_by_desc(entity::Column::CreatedAt)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }

    async fn save_snapshot(
        &self,
        context: AccountContext,
        snapshot: &Snapshot,
    ) -> box_core::Result<()> {
        if snapshot.account_id != context.account_id || snapshot.tenant_id != context.tenant_id {
            return Err(DomainError::ownership());
        }
        let result = entity::Entity::update_many()
            .col_expr(
                entity::Column::Name,
                sea_orm::sea_query::Expr::value(&snapshot.name),
            )
            .col_expr(
                entity::Column::Status,
                sea_orm::sea_query::Expr::value(text(&snapshot.status)),
            )
            .col_expr(
                entity::Column::DiskPath,
                sea_orm::sea_query::Expr::value(snapshot.disk_path.clone()),
            )
            .col_expr(
                entity::Column::SizeBytes,
                sea_orm::sea_query::Expr::value(
                    i64::try_from(snapshot.size_bytes)
                        .map_err(|_| DomainError::validation("snapshot size is too large"))?,
                ),
            )
            .col_expr(
                entity::Column::Checksum,
                sea_orm::sea_query::Expr::value(snapshot.checksum.clone()),
            )
            .col_expr(
                entity::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(snapshot.updated_at.as_millis()),
            )
            .filter(entity::Column::Id.eq(snapshot.id.to_string()))
            .filter(entity::Column::AccountId.eq(context.account_id.to_string()))
            .filter(entity::Column::TenantId.eq(context.tenant_id.to_string()))
            .exec(self.database.connection())
            .await
            .map_err(internal)?;
        if result.rows_affected == 1 {
            Ok(())
        } else {
            Err(DomainError::ownership())
        }
    }
}
