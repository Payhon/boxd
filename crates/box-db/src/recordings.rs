use box_browser::{
    BrowserRecording, BrowserRecordingId, BrowserRecordingMarker, BrowserRecordingRepository,
    BrowserRecordingStatus, BrowserRecordingUsage,
};
use box_core::{AccountContext, BoxId, DomainError, UtcEpochMillis};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};

use crate::{DatabaseHandle, internal, parse, scope, text};

mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "browser_recordings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub tenant_id: String,
        pub box_id: String,
        pub status: String,
        pub started_at: i64,
        pub ended_at: Option<i64>,
        pub duration_ms: Option<i64>,
        pub size_bytes: Option<i64>,
        pub segment_count: Option<i64>,
        pub mp4_size_bytes: Option<i64>,
        pub stopped_reason: Option<String>,
        pub max_duration_seconds: i64,
        pub playlist_path: Option<String>,
        pub path: Option<String>,
        pub markers_json: Option<String>,
        pub retention_at: i64,
        pub created_at: i64,
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
pub struct BrowserRecordingStore {
    database: DatabaseHandle,
}

impl BrowserRecordingStore {
    pub fn new(database: DatabaseHandle) -> Self {
        Self { database }
    }
}

fn db_u64(value: u64, field: &str) -> box_core::Result<i64> {
    i64::try_from(value).map_err(|_| DomainError::validation(format!("{field} is too large")))
}

fn model(recording: &BrowserRecording) -> box_core::Result<entity::ActiveModel> {
    Ok(entity::ActiveModel {
        id: Set(recording.id.to_string()),
        account_id: Set(recording.account_id.to_string()),
        tenant_id: Set(recording.tenant_id.to_string()),
        box_id: Set(recording.box_id.to_string()),
        status: Set(text(&recording.status)),
        started_at: Set(recording.started_at.as_millis()),
        ended_at: Set(recording.ended_at.map(UtcEpochMillis::as_millis)),
        duration_ms: Set(recording
            .duration_ms
            .map(|value| db_u64(value, "recording duration"))
            .transpose()?),
        size_bytes: Set(recording
            .size_bytes
            .map(|value| db_u64(value, "recording size"))
            .transpose()?),
        segment_count: Set(recording.segment_count.map(i64::from)),
        mp4_size_bytes: Set(recording
            .mp4_size_bytes
            .map(|value| db_u64(value, "recording MP4 size"))
            .transpose()?),
        stopped_reason: Set(recording.stopped_reason.clone()),
        max_duration_seconds: Set(i64::from(recording.max_duration_seconds)),
        playlist_path: Set(recording.playlist_path.clone()),
        path: Set(recording.download_path.clone()),
        markers_json: Set(Some(
            serde_json::to_string(&recording.markers).map_err(internal)?,
        )),
        retention_at: Set(recording.retention_at.as_millis()),
        created_at: Set(recording.started_at.as_millis()),
        updated_at: Set(recording.updated_at.as_millis()),
    })
}

fn domain(value: entity::Model) -> box_core::Result<BrowserRecording> {
    Ok(BrowserRecording {
        id: BrowserRecordingId::parse(&value.id)?,
        account_id: box_core::AccountId::parse(&value.account_id)?,
        tenant_id: box_core::TenantId::parse(&value.tenant_id)?,
        box_id: BoxId::parse(&value.box_id)?,
        status: parse::<BrowserRecordingStatus>(&value.status)?,
        started_at: UtcEpochMillis::from_millis(value.started_at),
        ended_at: value.ended_at.map(UtcEpochMillis::from_millis),
        duration_ms: value
            .duration_ms
            .map(u64::try_from)
            .transpose()
            .map_err(internal)?,
        size_bytes: value
            .size_bytes
            .map(u64::try_from)
            .transpose()
            .map_err(internal)?,
        segment_count: value
            .segment_count
            .map(u32::try_from)
            .transpose()
            .map_err(internal)?,
        mp4_size_bytes: value
            .mp4_size_bytes
            .map(u64::try_from)
            .transpose()
            .map_err(internal)?,
        stopped_reason: value.stopped_reason,
        max_duration_seconds: u32::try_from(value.max_duration_seconds).map_err(internal)?,
        markers: value
            .markers_json
            .as_deref()
            .map(parse::<Vec<BrowserRecordingMarker>>)
            .transpose()?
            .unwrap_or_default(),
        playlist_path: value.playlist_path,
        download_path: value.path,
        retention_at: UtcEpochMillis::from_millis(value.retention_at),
        updated_at: UtcEpochMillis::from_millis(value.updated_at),
    })
}

fn scoped(context: AccountContext, box_id: BoxId) -> sea_orm::Select<entity::Entity> {
    let (account, tenant) = scope(context);
    entity::Entity::find()
        .filter(entity::Column::AccountId.eq(account))
        .filter(entity::Column::TenantId.eq(tenant))
        .filter(entity::Column::BoxId.eq(box_id.to_string()))
}

#[async_trait::async_trait]
impl BrowserRecordingRepository for BrowserRecordingStore {
    async fn create(
        &self,
        context: AccountContext,
        recording: &BrowserRecording,
    ) -> box_core::Result<()> {
        recording.validate_scope(context)?;
        entity::Entity::insert(model(recording)?)
            .exec(self.database.connection())
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn save(
        &self,
        context: AccountContext,
        recording: &BrowserRecording,
    ) -> box_core::Result<()> {
        recording.validate_scope(context)?;
        let current = scoped(context, recording.box_id)
            .filter(entity::Column::Id.eq(recording.id.to_string()))
            .one(self.database.connection())
            .await
            .map_err(internal)?
            .ok_or_else(DomainError::ownership)?;
        let mut active = model(recording)?;
        active.id = sea_orm::ActiveValue::Unchanged(current.id);
        active
            .update(self.database.connection())
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn find(
        &self,
        context: AccountContext,
        box_id: BoxId,
        id: BrowserRecordingId,
    ) -> box_core::Result<Option<BrowserRecording>> {
        scoped(context, box_id)
            .filter(entity::Column::Id.eq(id.to_string()))
            .one(self.database.connection())
            .await
            .map_err(internal)?
            .map(domain)
            .transpose()
    }

    async fn list(
        &self,
        context: AccountContext,
        box_id: BoxId,
        cursor: Option<BrowserRecordingId>,
        limit: usize,
    ) -> box_core::Result<Vec<BrowserRecording>> {
        if limit == 0 || limit > 101 {
            return Err(DomainError::validation("invalid recording list limit"));
        }
        let mut query = scoped(context, box_id);
        if let Some(cursor) = cursor {
            query = query.filter(entity::Column::Id.lt(cursor.to_string()));
        }
        query
            .order_by_desc(entity::Column::Id)
            .limit(u64::try_from(limit).map_err(internal)?)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }

    async fn active(
        &self,
        context: AccountContext,
        box_id: BoxId,
    ) -> box_core::Result<Option<BrowserRecording>> {
        scoped(context, box_id)
            .filter(entity::Column::Status.eq(text(&BrowserRecordingStatus::Recording)))
            .order_by_desc(entity::Column::Id)
            .one(self.database.connection())
            .await
            .map_err(internal)?
            .map(domain)
            .transpose()
    }

    async fn active_all(&self) -> box_core::Result<Vec<BrowserRecording>> {
        entity::Entity::find()
            .filter(entity::Column::Status.eq(text(&BrowserRecordingStatus::Recording)))
            .order_by_asc(entity::Column::Id)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }

    async fn usage(&self, context: AccountContext) -> box_core::Result<BrowserRecordingUsage> {
        let (account, tenant) = scope(context);
        let values = entity::Entity::find()
            .filter(entity::Column::AccountId.eq(account))
            .filter(entity::Column::TenantId.eq(tenant))
            .filter(entity::Column::Status.ne(text(&BrowserRecordingStatus::Deleted)))
            .all(self.database.connection())
            .await
            .map_err(internal)?;
        let retained_bytes = values.iter().try_fold(0_u64, |total, value| {
            let size = value
                .size_bytes
                .map(u64::try_from)
                .transpose()
                .map_err(internal)?
                .unwrap_or_default();
            total
                .checked_add(size)
                .ok_or_else(|| DomainError::validation("recording usage overflow"))
        })?;
        let active_count = u32::try_from(
            values
                .iter()
                .filter(|value| value.status == text(&BrowserRecordingStatus::Recording))
                .count(),
        )
        .map_err(internal)?;
        Ok(BrowserRecordingUsage {
            retained_bytes,
            active_count,
        })
    }

    async fn expired(
        &self,
        at: UtcEpochMillis,
        limit: usize,
    ) -> box_core::Result<Vec<BrowserRecording>> {
        if limit == 0 || limit > 1_000 {
            return Err(DomainError::validation("invalid recording expiry limit"));
        }
        entity::Entity::find()
            .filter(entity::Column::Status.ne(text(&BrowserRecordingStatus::Deleted)))
            .filter(entity::Column::Status.ne(text(&BrowserRecordingStatus::Recording)))
            .filter(entity::Column::RetentionAt.lte(at.as_millis()))
            .order_by_asc(entity::Column::RetentionAt)
            .order_by_asc(entity::Column::Id)
            .limit(u64::try_from(limit).map_err(internal)?)
            .all(self.database.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(domain)
            .collect()
    }
}
