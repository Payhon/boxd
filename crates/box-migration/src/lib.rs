//! Portable SeaORM migrations. JSON values are stored as canonical text so the
//! same schema works on SQLite, PostgreSQL, and MySQL.

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(InitialSchema),
            Box::new(AuthSchema),
            Box::new(SecretSchema),
            Box::new(AccountSecretSchema),
            Box::new(RuntimeBundleBindingSchema),
            Box::new(RunContractSchema),
            Box::new(SnapshotRestoreBindingSchema),
            Box::new(PreviewConstraintSchema),
            Box::new(SkillSchema),
            Box::new(NetworkPolicyTextSchema),
        ]
    }
}

struct NetworkPolicyTextSchema;
impl MigrationName for NetworkPolicyTextSchema {
    fn name(&self) -> &str {
        "m0010_network_policy_text"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for NetworkPolicyTextSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite does not enforce VARCHAR lengths and cannot portably alter a
        // column type in place. Fresh SQLite schemas already use TEXT below.
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("boxes"))
                    .modify_column(
                        ColumnDef::new(Alias::new("network_policy"))
                            .text()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("boxes"))
                    .modify_column(
                        ColumnDef::new(Alias::new("network_policy"))
                            .string_len(32)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

struct SkillSchema;
impl MigrationName for SkillSchema {
    fn name(&self) -> &str {
        "m0009_box_skills"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for SkillSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("box_skills"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("account_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("tenant_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("box_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("skill_id"))
                            .string_len(384)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("name"))
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("source_commit"))
                            .string_len(40)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("content_sha256"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("updated_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_box_skills_box_owner")
                            .from(
                                Alias::new("box_skills"),
                                (
                                    Alias::new("account_id"),
                                    Alias::new("tenant_id"),
                                    Alias::new("box_id"),
                                ),
                            )
                            .to(
                                Alias::new("boxes"),
                                (
                                    Alias::new("account_id"),
                                    Alias::new("tenant_id"),
                                    Alias::new("id"),
                                ),
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_box_skills_owner_skill")
                    .table(Alias::new("box_skills"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("box_id"))
                    .col(Alias::new("skill_id"))
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_box_skills_owner_name")
                    .table(Alias::new("box_skills"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("box_id"))
                    .col(Alias::new("name"))
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Alias::new("box_skills")).to_owned())
            .await
    }
}

struct PreviewConstraintSchema;
impl MigrationName for PreviewConstraintSchema {
    fn name(&self) -> &str {
        "m0008_preview_constraints"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for PreviewConstraintSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("uq_previews_owner_port")
                    .table(Alias::new("previews"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("box_id"))
                    .col(Alias::new("port"))
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_previews_token_hmac")
                    .table(Alias::new("previews"))
                    .col(Alias::new("token_hmac"))
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("uq_previews_token_hmac")
                    .table(Alias::new("previews"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("uq_previews_owner_port")
                    .table(Alias::new("previews"))
                    .to_owned(),
            )
            .await
    }
}

struct SnapshotRestoreBindingSchema;
impl MigrationName for SnapshotRestoreBindingSchema {
    fn name(&self) -> &str {
        "m0007_snapshot_restore_binding"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for SnapshotRestoreBindingSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("boxes"))
                    .add_column(ColumnDef::new(Alias::new("source_snapshot_id")).string_len(36))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("boxes"))
                    .drop_column(Alias::new("source_snapshot_id"))
                    .to_owned(),
            )
            .await
    }
}

struct RunContractSchema;
impl MigrationName for RunContractSchema {
    fn name(&self) -> &str {
        "m0006_run_contract"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for RunContractSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("runs"))
                    .add_column(ColumnDef::new(Alias::new("model")).string_len(255))
                    .to_owned(),
            )
            .await?;
        for name in [
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "cost_microusd",
            "duration_ms",
            "compute_cost_microusd",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("runs"))
                        .add_column(
                            ColumnDef::new(Alias::new(name))
                                .big_integer()
                                .not_null()
                                .default(0),
                        )
                        .to_owned(),
                )
                .await?;
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("runs"))
                    .add_column(ColumnDef::new(Alias::new("completed_at")).big_integer())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in [
            "completed_at",
            "compute_cost_microusd",
            "duration_ms",
            "cost_microusd",
            "cached_input_tokens",
            "output_tokens",
            "input_tokens",
            "model",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("runs"))
                        .drop_column(Alias::new(name))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

struct RuntimeBundleBindingSchema;
impl MigrationName for RuntimeBundleBindingSchema {
    fn name(&self) -> &str {
        "m0005_runtime_bundle_binding"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for RuntimeBundleBindingSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, length) in [
            ("runtime_bundle_sha256", 64),
            ("runtime_version", 128),
            ("runtime_arch", 16),
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("boxes"))
                        .add_column(ColumnDef::new(Alias::new(name)).string_len(length))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in ["runtime_arch", "runtime_version", "runtime_bundle_sha256"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("boxes"))
                        .drop_column(Alias::new(name))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(DeriveMigrationName)]
struct InitialSchema;

struct AuthSchema;
impl MigrationName for AuthSchema {
    fn name(&self) -> &str {
        "m0002_auth_schema"
    }
}

struct SecretSchema;
impl MigrationName for SecretSchema {
    fn name(&self) -> &str {
        "m0003_secret_schema"
    }
}

struct AccountSecretSchema;
impl MigrationName for AccountSecretSchema {
    fn name(&self) -> &str {
        "m0004_account_secret_schema"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for AccountSecretSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("account_secrets"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("account_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("tenant_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("kind")).string_len(32).not_null())
                    .col(
                        ColumnDef::new(Alias::new("name"))
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("ciphertext")).text().not_null())
                    .col(ColumnDef::new(Alias::new("nonce")).text().not_null())
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("updated_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_account_secrets_account")
                            .from(Alias::new("account_secrets"), Alias::new("account_id"))
                            .to(Alias::new("accounts"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_account_secrets_scope_name")
                    .table(Alias::new("account_secrets"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("kind"))
                    .col(Alias::new("name"))
                    .unique()
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("account_secrets"))
                    .to_owned(),
            )
            .await
    }
}

#[async_trait::async_trait]
impl MigrationTrait for SecretSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("uq_box_secrets_scope_name")
                    .table(Alias::new("box_secrets"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("box_id"))
                    .col(Alias::new("kind"))
                    .col(Alias::new("name"))
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("uq_box_secrets_scope_name")
                    .table(Alias::new("box_secrets"))
                    .to_owned(),
            )
            .await
    }
}

#[async_trait::async_trait]
impl MigrationTrait for AuthSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("uq_users_owner_id")
                    .table(Alias::new("users"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("id"))
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Alias::new("admin_sessions"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("account_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("tenant_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("user_id"))
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("token_prefix"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("token_hmac"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("csrf_hmac"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("expires_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("revoked_at")).big_integer())
                    .col(ColumnDef::new(Alias::new("last_seen_at")).big_integer())
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("updated_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_admin_sessions_user_owner")
                            .from(
                                Alias::new("admin_sessions"),
                                (
                                    Alias::new("account_id"),
                                    Alias::new("tenant_id"),
                                    Alias::new("user_id"),
                                ),
                            )
                            .to(
                                Alias::new("users"),
                                (
                                    Alias::new("account_id"),
                                    Alias::new("tenant_id"),
                                    Alias::new("id"),
                                ),
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_admin_sessions_prefix")
                    .table(Alias::new("admin_sessions"))
                    .col(Alias::new("token_prefix"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("uq_admin_sessions_token_hmac")
                    .table(Alias::new("admin_sessions"))
                    .col(Alias::new("token_hmac"))
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_admin_sessions_owner_user")
                    .table(Alias::new("admin_sessions"))
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("user_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Alias::new("bootstrap_state"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("completed_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("bootstrap_state"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Alias::new("admin_sessions")).to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("uq_users_owner_id")
                    .table(Alias::new("users"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl MigrationTrait for InitialSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in CREATE_ORDER {
            let table = TABLES.iter().find(|table| table.name == *name).unwrap();
            manager.create_table(table.create()).await?;
        }
        for index in INDEXES {
            manager.create_index(index.create()).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in CREATE_ORDER.iter().rev() {
            manager
                .drop_table(Table::drop().table(Alias::new(*name)).to_owned())
                .await?;
        }
        Ok(())
    }
}

struct TableSpec {
    name: &'static str,
    columns: &'static [&'static str],
}
impl TableSpec {
    fn create(&self) -> TableCreateStatement {
        let mut table = Table::create();
        table.table(Alias::new(self.name)).if_not_exists();
        for column in self.columns {
            let mut def = ColumnDef::new(Alias::new(*column));
            let required = !nullable(self.name, column);
            match column_kind(self.name, column) {
                ColumnKind::String(length) => {
                    def.string_len(length);
                }
                ColumnKind::Text => {
                    def.text();
                }
                ColumnKind::BigInteger => {
                    def.big_integer();
                }
                ColumnKind::Integer => {
                    def.integer();
                }
                ColumnKind::Boolean => {
                    def.boolean().default(false);
                }
            }
            if required {
                def.not_null();
            }
            if *column == "id" {
                def.primary_key();
            }
            table.col(&mut def);
        }
        for (column, target) in foreign_keys(self.name) {
            table.foreign_key(
                &mut ForeignKey::create()
                    .name(format!("fk_{}_{}", self.name, column))
                    .from(Alias::new(self.name), Alias::new(*column))
                    .to(Alias::new(*target), Alias::new("id"))
                    .to_owned(),
            );
        }
        if matches!(self.name, "boxes" | "runs" | "schedules") {
            table.index(
                Index::create()
                    .unique()
                    .col(Alias::new("account_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("id")),
            );
        }
        if box_child(self.name) {
            table.foreign_key(
                ForeignKey::create()
                    .name(format!("fk_{}_box_owner", self.name))
                    .from(
                        Alias::new(self.name),
                        (
                            Alias::new("account_id"),
                            Alias::new("tenant_id"),
                            Alias::new("box_id"),
                        ),
                    )
                    .to(
                        Alias::new("boxes"),
                        (
                            Alias::new("account_id"),
                            Alias::new("tenant_id"),
                            Alias::new("id"),
                        ),
                    )
                    .on_delete(box_child_delete_action(self.name)),
            );
        }
        if self.name == "run_events" {
            table.foreign_key(
                ForeignKey::create()
                    .name("fk_run_events_run_owner")
                    .from(
                        Alias::new("run_events"),
                        (
                            Alias::new("account_id"),
                            Alias::new("tenant_id"),
                            Alias::new("run_id"),
                        ),
                    )
                    .to(
                        Alias::new("runs"),
                        (
                            Alias::new("account_id"),
                            Alias::new("tenant_id"),
                            Alias::new("id"),
                        ),
                    )
                    .on_delete(ForeignKeyAction::Cascade),
            );
        }
        if self.name == "runs" {
            table.foreign_key(
                ForeignKey::create()
                    .name("fk_runs_schedule_owner")
                    .from(
                        Alias::new("runs"),
                        (
                            Alias::new("account_id"),
                            Alias::new("tenant_id"),
                            Alias::new("schedule_id"),
                        ),
                    )
                    .to(
                        Alias::new("schedules"),
                        (
                            Alias::new("account_id"),
                            Alias::new("tenant_id"),
                            Alias::new("id"),
                        ),
                    ),
            );
        }
        table.to_owned()
    }
}

enum ColumnKind {
    String(u32),
    Text,
    BigInteger,
    Integer,
    Boolean,
}

/// Explicit portable SQL types. In particular, indexed and referenced IDs use
/// bounded strings rather than backend-specific or unindexable TEXT columns.
fn column_kind(table: &str, column: &str) -> ColumnKind {
    if (table, column) == ("runtime_images", "version") {
        return ColumnKind::String(128);
    }
    match column {
        "id" | "account_id" | "tenant_id" | "node_id" | "box_id" | "schedule_id" | "run_id" => {
            ColumnKind::String(36)
        }
        "label" => ColumnKind::String(20),
        "prefix" => ColumnKind::String(64),
        "key_hmac" | "token_hmac" => ColumnKind::String(64),
        "idempotency_key" => ColumnKind::String(128),
        "username" | "request_id" | "checksum" => ColumnKind::String(128),
        "role" | "platform" | "arch" | "runtime" | "size" | "status" | "kind" | "type"
        | "event_type" | "auth" | "stopped_reason" => ColumnKind::String(32),
        "timezone" | "ip" | "cost" => ColumnKind::String(64),
        "name" | "password_hash" | "model" | "lease_token" | "nonce" | "cron" | "actor"
        | "action" | "resource" | "session_id" => ColumnKind::String(255),
        "scopes_json" | "capabilities_json" | "agent_json" | "counters_json" | "ciphertext"
        | "prompt" | "output" | "error" | "payload_json" | "manifest_json" | "markers_json"
        | "metadata_json" | "disk_path" | "path" | "playlist_path" | "network_policy" => {
            ColumnKind::Text
        }
        "created_at"
        | "updated_at"
        | "last_used_at"
        | "expires_at"
        | "heartbeat_at"
        | "lease_expires_at"
        | "next_run_at"
        | "retention_at"
        | "version"
        | "sequence"
        | "retry_count"
        | "disk_bytes"
        | "size_bytes"
        | "cpu_ns"
        | "memory_bytes"
        | "token_count"
        | "started_at"
        | "ended_at"
        | "duration_ms"
        | "segment_count"
        | "mp4_size_bytes"
        | "max_duration_seconds" => ColumnKind::BigInteger,
        "port" | "position" => ColumnKind::Integer,
        "ephemeral" | "keep_alive" | "browser" | "paused" => ColumnKind::Boolean,
        other => panic!("migration column {other} has no explicit portable SQL type"),
    }
}

fn box_child(table: &str) -> bool {
    matches!(
        table,
        "box_labels"
            | "box_secrets"
            | "runs"
            | "snapshots"
            | "schedules"
            | "previews"
            | "browser_recordings"
            | "operations"
    )
}

fn box_child_delete_action(table: &str) -> ForeignKeyAction {
    match table {
        "snapshots" | "operations" => ForeignKeyAction::Restrict,
        _ => ForeignKeyAction::Cascade,
    }
}

fn nullable(table: &str, column: &str) -> bool {
    matches!(
        (table, column),
        ("api_keys", "last_used_at" | "expires_at")
            | ("nodes", "heartbeat_at")
            | (
                "boxes",
                "node_id"
                    | "name"
                    | "expires_at"
                    | "model"
                    | "agent_json"
                    | "counters_json"
                    | "browser"
                    | "disk_bytes"
                    | "lease_token"
                    | "lease_expires_at"
            )
            | ("operations", "box_id" | "error")
            | (
                "runs",
                "schedule_id"
                    | "prompt"
                    | "output"
                    | "error"
                    | "token_count"
                    | "cpu_ns"
                    | "memory_bytes"
                    | "cost"
                    | "session_id"
            )
            | ("snapshots", "disk_path" | "checksum")
            | (
                "schedules",
                "next_run_at" | "lease_token" | "lease_expires_at"
            )
            | ("runtime_images", "manifest_json" | "path" | "checksum")
            | (
                "browser_recordings",
                "ended_at"
                    | "duration_ms"
                    | "size_bytes"
                    | "segment_count"
                    | "mp4_size_bytes"
                    | "stopped_reason"
                    | "playlist_path"
                    | "path"
                    | "markers_json"
            )
            | ("audit_logs", "request_id" | "ip" | "metadata_json")
    )
}
fn foreign_keys(table: &str) -> &'static [(&'static str, &'static str)] {
    match table {
        "users" | "api_keys" | "audit_logs" => &[("account_id", "accounts")],
        "boxes" => &[("account_id", "accounts"), ("node_id", "nodes")],
        _ => &[],
    }
}

const CREATE_ORDER: &[&str] = &[
    "accounts",
    "users",
    "api_keys",
    "nodes",
    "boxes",
    "box_labels",
    "box_secrets",
    "schedules",
    "runs",
    "run_events",
    "snapshots",
    "previews",
    "runtime_images",
    "browser_recordings",
    "operations",
    "audit_logs",
];
struct IndexSpec {
    name: &'static str,
    table: &'static str,
    cols: &'static [&'static str],
    unique: bool,
}
impl IndexSpec {
    fn create(&self) -> IndexCreateStatement {
        let mut index = Index::create();
        index.name(self.name).table(Alias::new(self.table));
        for col in self.cols {
            index.col(Alias::new(*col));
        }
        if self.unique {
            index.unique();
        }
        index.to_owned()
    }
}

// All tenant-owned data carries both account_id and tenant_id. IDs are UUIDv7
// strings. Relation integrity is enforced with portable foreign keys.
const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "accounts",
        columns: &["id", "name", "status", "created_at", "updated_at"],
    },
    TableSpec {
        name: "users",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "username",
            "password_hash",
            "role",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "api_keys",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "prefix",
            "key_hmac",
            "scopes_json",
            "last_used_at",
            "expires_at",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "nodes",
        columns: &[
            "id",
            "platform",
            "arch",
            "capabilities_json",
            "heartbeat_at",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "boxes",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "node_id",
            "name",
            "runtime",
            "size",
            "status",
            "ephemeral",
            "expires_at",
            "keep_alive",
            "browser",
            "disk_bytes",
            "model",
            "agent_json",
            "counters_json",
            "network_policy",
            "lease_token",
            "lease_expires_at",
            "version",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "box_labels",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "label",
            "position",
            "created_at",
        ],
    },
    TableSpec {
        name: "box_secrets",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "kind",
            "name",
            "ciphertext",
            "nonce",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "runs",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "schedule_id",
            "type",
            "status",
            "prompt",
            "output",
            "error",
            "token_count",
            "cpu_ns",
            "memory_bytes",
            "cost",
            "session_id",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "run_events",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "run_id",
            "sequence",
            "event_type",
            "payload_json",
            "created_at",
        ],
    },
    TableSpec {
        name: "snapshots",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "name",
            "status",
            "disk_path",
            "size_bytes",
            "checksum",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "schedules",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "cron",
            "timezone",
            "payload_json",
            "paused",
            "next_run_at",
            "lease_token",
            "lease_expires_at",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "previews",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "port",
            "auth",
            "token_hmac",
            "expires_at",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "runtime_images",
        columns: &[
            "id",
            "runtime",
            "arch",
            "version",
            "manifest_json",
            "path",
            "checksum",
            "status",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "browser_recordings",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "status",
            "started_at",
            "ended_at",
            "duration_ms",
            "size_bytes",
            "segment_count",
            "mp4_size_bytes",
            "stopped_reason",
            "max_duration_seconds",
            "playlist_path",
            "path",
            "markers_json",
            "retention_at",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "operations",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "box_id",
            "kind",
            "status",
            "idempotency_key",
            "retry_count",
            "error",
            "created_at",
            "updated_at",
        ],
    },
    TableSpec {
        name: "audit_logs",
        columns: &[
            "id",
            "account_id",
            "tenant_id",
            "actor",
            "action",
            "resource",
            "request_id",
            "ip",
            "metadata_json",
            "created_at",
        ],
    },
];
const INDEXES: &[IndexSpec] = &[
    IndexSpec {
        name: "uq_users_scope_username",
        table: "users",
        cols: &["account_id", "tenant_id", "username"],
        unique: true,
    },
    IndexSpec {
        name: "idx_api_keys_prefix",
        table: "api_keys",
        cols: &["prefix"],
        unique: false,
    },
    IndexSpec {
        name: "uq_api_keys_hmac",
        table: "api_keys",
        cols: &["key_hmac"],
        unique: true,
    },
    IndexSpec {
        name: "uq_box_labels",
        table: "box_labels",
        cols: &["account_id", "tenant_id", "box_id", "label"],
        unique: true,
    },
    IndexSpec {
        name: "uq_box_label_positions",
        table: "box_labels",
        cols: &["account_id", "tenant_id", "box_id", "position"],
        unique: true,
    },
    // Keep the ownership FK index separate from the later kind+name unique
    // constraint. MySQL may otherwise reuse the unique index for the FK and
    // make the reversible SecretSchema migration impossible to roll back.
    IndexSpec {
        name: "idx_box_secrets_scope_box",
        table: "box_secrets",
        cols: &["account_id", "tenant_id", "box_id"],
        unique: false,
    },
    IndexSpec {
        name: "uq_run_events",
        table: "run_events",
        cols: &["account_id", "tenant_id", "run_id", "sequence"],
        unique: true,
    },
    IndexSpec {
        name: "uq_operations_idempotency",
        table: "operations",
        cols: &["account_id", "tenant_id", "kind", "idempotency_key"],
        unique: true,
    },
    IndexSpec {
        name: "idx_boxes_scope",
        table: "boxes",
        cols: &["account_id", "tenant_id"],
        unique: false,
    },
    IndexSpec {
        name: "idx_runs_scope_box",
        table: "runs",
        cols: &["account_id", "tenant_id", "box_id"],
        unique: false,
    },
    IndexSpec {
        name: "idx_snapshots_scope_box",
        table: "snapshots",
        cols: &["account_id", "tenant_id", "box_id"],
        unique: false,
    },
    IndexSpec {
        name: "idx_browser_recordings_scope_box_time",
        table: "browser_recordings",
        cols: &["account_id", "tenant_id", "box_id", "started_at"],
        unique: false,
    },
    // MySQL requires a child-side index for the composite preview -> box
    // ownership FK. Keep it independent from the later owner+port unique
    // constraint so that migration can be rolled back without dropping the
    // FK's only supporting index.
    IndexSpec {
        name: "idx_previews_scope_box",
        table: "previews",
        cols: &["account_id", "tenant_id", "box_id"],
        unique: false,
    },
    IndexSpec {
        name: "idx_audit_scope_time",
        table: "audit_logs",
        cols: &["account_id", "tenant_id", "created_at"],
        unique: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};
    #[tokio::test]
    async fn sqlite_migration_is_reversible() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared("SELECT * FROM boxes").await.unwrap();
        let columns = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA table_info(boxes)",
            ))
            .await
            .unwrap();
        let network_policy = columns
            .iter()
            .find(|column| column.try_get_by_index::<String>(1).unwrap() == "network_policy")
            .expect("fresh boxes schema must contain network_policy");
        assert_eq!(
            network_policy.try_get_by_index::<String>(2).unwrap(),
            "TEXT"
        );
        Migrator::down(&db, None).await.unwrap();
        assert!(db.execute_unprepared("SELECT * FROM boxes").await.is_err());
    }

    #[tokio::test]
    async fn optional_postgres_and_mysql_migrations() {
        let mut configured = 0;
        for variable in ["BOXD_TEST_POSTGRES_URL", "BOXD_TEST_MYSQL_URL"] {
            let Ok(url) = std::env::var(variable) else {
                eprintln!("skipping {variable}: environment variable is not configured");
                continue;
            };
            configured += 1;
            let db = Database::connect(url).await.unwrap();
            Migrator::up(&db, None).await.unwrap();
            Migrator::down(&db, None).await.unwrap();
        }
        if configured == 0 {
            eprintln!("PostgreSQL/MySQL runtime migration checks explicitly skipped");
        }
    }
}
