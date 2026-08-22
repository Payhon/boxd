//! Startup migration guard: consistent SQLite backup plus an atomic journal.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::MigratorTrait;
use sha2::{Digest, Sha256};

use crate::{DatabaseHandle, internal, migrate, sqlite_database_path};

#[derive(serde::Serialize)]
struct Journal {
    format: &'static str,
    state: &'static str,
    pending_migrations: Vec<String>,
    applied_migrations_before: Vec<String>,
    applied_migrations_after: Vec<String>,
    backup: Option<BackupBinding>,
    updated_at_ms: u128,
}

#[derive(Clone, serde::Serialize)]
struct BackupBinding {
    path: String,
    sha256: String,
}

/// Migrate while preserving a consistent pre-migration SQLite image.
/// Non-SQLite backends deliberately use the ordinary forward-only migrator.
pub async fn guarded_migrate(db: &DatabaseHandle, data_dir: &Path) -> box_core::Result<()> {
    let Some(database_path) = sqlite_database_path(db) else {
        return migrate(db).await;
    };
    let root = secure_root(data_dir)?;
    let journal_path = root.join("migration-journal.json");
    validate_existing_journal(&journal_path)?;
    let pending = box_migration::Migrator::get_pending_migrations_read_only(db.connection())
        .await
        .map_err(internal)?;
    if pending.is_empty() {
        return Ok(());
    }
    let pending_names = pending
        .iter()
        .map(|migration| migration.name().to_owned())
        .collect::<Vec<_>>();
    let applied_before = applied_migrations(db).await?;
    let backup = if sqlite_has_user_objects(db).await? {
        Some(create_backup(db, database_path, &root).await?)
    } else {
        None
    };
    reject_existing_output(&journal_path, true)?;
    write_journal(
        &journal_path,
        &Journal {
            format: "boxd-migration-journal-v1",
            state: "prepared",
            pending_migrations: pending_names.clone(),
            applied_migrations_before: applied_before.clone(),
            applied_migrations_after: Vec::new(),
            backup: backup.clone(),
            updated_at_ms: now(),
        },
    )?;

    if let Err(error) = box_migration::Migrator::up(db.connection(), None).await {
        let _ = write_journal(
            &journal_path,
            &Journal {
                format: "boxd-migration-journal-v1",
                state: "failed",
                pending_migrations: pending_names.clone(),
                applied_migrations_before: applied_before.clone(),
                applied_migrations_after: applied_migrations(db).await.unwrap_or_default(),
                backup: backup.clone(),
                updated_at_ms: now(),
            },
        );
        return Err(internal(error));
    }
    if let Err(error) = db
        .execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE)")
        .await
    {
        let _ = write_journal(
            &journal_path,
            &Journal {
                format: "boxd-migration-journal-v1",
                state: "failed",
                pending_migrations: pending_names.clone(),
                applied_migrations_before: applied_before,
                applied_migrations_after: applied_migrations(db).await.unwrap_or_default(),
                backup: backup.clone(),
                updated_at_ms: now(),
            },
        );
        return Err(internal(error));
    }
    let applied = applied_migrations(db).await?;
    write_journal(
        &journal_path,
        &Journal {
            format: "boxd-migration-journal-v1",
            state: "applied",
            pending_migrations: pending_names,
            applied_migrations_before: applied_before,
            applied_migrations_after: applied,
            backup,
            updated_at_ms: now(),
        },
    )
}

fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn secure_root(path: &Path) -> box_core::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(box_core::DomainError::validation(
            "migration data directory must be absolute",
        ));
    }
    let meta = fs::symlink_metadata(path).map_err(internal)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(box_core::DomainError::validation(
            "migration data directory must be a real directory",
        ));
    }
    path.canonicalize().map_err(internal)
}

fn reject_existing_output(path: &Path, allow_existing: bool) -> box_core::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(internal(error)),
    };
    #[cfg(unix)]
    if meta.nlink() != 1 {
        return Err(box_core::DomainError::validation(
            "migration output must not be hard-linked",
        ));
    }
    if meta.file_type().is_symlink() || !meta.is_file() || !allow_existing {
        return Err(box_core::DomainError::validation(
            "migration output is unsafe or already exists",
        ));
    }
    Ok(())
}

fn validate_existing_journal(path: &Path) -> box_core::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(internal(error)),
    };
    #[cfg(unix)]
    if meta.nlink() != 1 {
        return Err(box_core::DomainError::validation(
            "migration journal must not be hard-linked",
        ));
    }
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(box_core::DomainError::validation(
            "migration journal must be a regular file",
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&fs::read(path).map_err(internal)?)
        .map_err(|_| box_core::DomainError::validation("migration journal is malformed"))?;
    if document.get("format").and_then(serde_json::Value::as_str)
        != Some("boxd-migration-journal-v1")
    {
        return Err(box_core::DomainError::validation(
            "migration journal format is unsupported",
        ));
    }
    match document.get("state").and_then(serde_json::Value::as_str) {
        Some("applied") => Ok(()),
        Some("prepared" | "failed") => Err(box_core::DomainError {
            kind: box_core::DomainErrorKind::Unavailable,
            code: "migration_recovery_required",
            message: "a prior SQLite migration did not reach an applied journal state".into(),
        }),
        _ => Err(box_core::DomainError::validation(
            "migration journal state is invalid",
        )),
    }
}

async fn create_backup(
    db: &DatabaseHandle,
    database_path: &Path,
    root: &Path,
) -> box_core::Result<BackupBinding> {
    let db_meta = fs::symlink_metadata(database_path).map_err(internal)?;
    if db_meta.file_type().is_symlink() || !db_meta.is_file() || db_meta.len() == 0 {
        return Err(box_core::DomainError::validation(
            "SQLite database file is unsafe or empty",
        ));
    }
    #[cfg(unix)]
    if db_meta.nlink() != 1 {
        return Err(box_core::DomainError::validation(
            "SQLite database must not be hard-linked",
        ));
    }
    let dir = root.join("migration-backups");
    if dir.exists() {
        let meta = fs::symlink_metadata(&dir).map_err(internal)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(box_core::DomainError::validation(
                "migration backup directory is unsafe",
            ));
        }
    } else {
        fs::create_dir(&dir).map_err(internal)?;
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(internal)?;
    if !dir.canonicalize().map_err(internal)?.starts_with(root) {
        return Err(box_core::DomainError::validation(
            "migration backup directory escapes data root",
        ));
    }
    let name = format!("{}.sqlite3", unique_id());
    let output = dir.join(name);
    reject_existing_output(&output, false)?;
    let escaped = output.to_string_lossy().replace('\'', "''");
    db.execute_unprepared(&format!("VACUUM INTO '{escaped}'"))
        .await
        .map_err(internal)?;
    let metadata = fs::symlink_metadata(&output).map_err(internal)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(box_core::DomainError::validation(
            "SQLite backup output is unsafe",
        ));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(box_core::DomainError::validation(
            "SQLite backup must not be hard-linked",
        ));
    }
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).map_err(internal)?;
    let mut file = File::open(&output).map_err(internal)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(internal)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let relative = output
        .strip_prefix(root)
        .map_err(internal)?
        .to_string_lossy()
        .to_string();
    if database_path.canonicalize().map_err(internal)? != database_path {
        return Err(box_core::DomainError::validation(
            "SQLite database path changed during migration backup",
        ));
    }
    Ok(BackupBinding {
        path: relative,
        sha256: hex::encode(digest.finalize()),
    })
}

fn write_journal(path: &Path, journal: &Journal) -> box_core::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(internal)?;
    let temp = path.with_file_name(format!(".migration-journal.{}.tmp", unique_id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temp).map_err(internal)?;
    if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(internal(error));
    }
    if let Err(error) = fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&temp);
        return Err(internal(error));
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(internal(error));
    }
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|parent| parent.sync_all())
        .map_err(internal)?;
    Ok(())
}

async fn sqlite_has_user_objects(db: &DatabaseHandle) -> box_core::Result<bool> {
    let row = db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, "SELECT COUNT(*) AS count FROM sqlite_master WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%'".to_owned())).await.map_err(internal)?;
    Ok(row
        .map(|r| r.try_get::<i64>("", "count").unwrap_or(0) > 0)
        .unwrap_or(false))
}

async fn applied_migrations(db: &DatabaseHandle) -> box_core::Result<Vec<String>> {
    Ok(
        box_migration::Migrator::get_applied_migrations_read_only(db.connection())
            .await
            .map_err(internal)?
            .into_iter()
            .map(|migration| migration.name().to_owned())
            .collect(),
    )
}

fn unique_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;
    use tempfile::TempDir;

    async fn open(temp: &TempDir) -> (DatabaseHandle, PathBuf) {
        let data = temp.path().join("data");
        fs::create_dir(&data).unwrap();
        let db_path = data.join("boxd.sqlite3");
        let url = format!("sqlite://{}?mode=rwc", db_path.display());
        (crate::connect(&url, 1).await.unwrap(), data)
    }

    #[tokio::test]
    async fn fresh_sqlite_writes_null_backup_journal() {
        let temp = tempfile::tempdir().unwrap();
        let (db, data) = open(&temp).await;
        guarded_migrate(&db, &data).await.unwrap();
        let journal: serde_json::Value =
            serde_json::from_slice(&fs::read(data.join("migration-journal.json")).unwrap())
                .unwrap();
        assert_eq!(journal["state"], "applied");
        assert!(journal["backup"].is_null());
    }

    #[tokio::test]
    async fn partial_sqlite_migration_has_reconnectable_backup_and_binding() {
        let temp = tempfile::tempdir().unwrap();
        let (db, data) = open(&temp).await;
        box_migration::Migrator::up(db.connection(), Some(1))
            .await
            .unwrap();
        db.execute_unprepared("CREATE TABLE migration_marker (value TEXT NOT NULL); INSERT INTO migration_marker VALUES ('before');").await.unwrap();
        guarded_migrate(&db, &data).await.unwrap();
        let journal: serde_json::Value =
            serde_json::from_slice(&fs::read(data.join("migration-journal.json")).unwrap())
                .unwrap();
        let binding = journal["backup"].as_object().unwrap();
        let backup = data.join(binding["path"].as_str().unwrap());
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut file = File::open(&backup).unwrap();
        let mut digest = Sha256::new();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        digest.update(&bytes);
        assert_eq!(binding["sha256"], hex::encode(digest.finalize()));
        drop(db);
        let backup_db = crate::connect(&format!("sqlite://{}?mode=rwc", backup.display()), 1)
            .await
            .unwrap();
        let marker = backup_db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT value FROM migration_marker".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(marker.try_get::<String>("", "value").unwrap(), "before");
        assert!(
            !journal["applied_migrations_after"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn no_pending_does_not_rewrite_journal() {
        let temp = tempfile::tempdir().unwrap();
        let (db, data) = open(&temp).await;
        guarded_migrate(&db, &data).await.unwrap();
        let path = data.join("migration-journal.json");
        let before = fs::read(&path).unwrap();
        guarded_migrate(&db, &data).await.unwrap();
        assert_eq!(before, fs::read(path).unwrap());
    }

    #[tokio::test]
    async fn unresolved_or_malformed_journal_blocks_restart_even_without_pending_migrations() {
        let temp = tempfile::tempdir().unwrap();
        let (db, data) = open(&temp).await;
        guarded_migrate(&db, &data).await.unwrap();
        let path = data.join("migration-journal.json");
        let mut journal: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        journal["state"] = serde_json::Value::String("failed".into());
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        let error = guarded_migrate(&db, &data).await.unwrap_err();
        assert_eq!(error.code, "migration_recovery_required");

        fs::write(&path, b"not-json").unwrap();
        assert!(guarded_migrate(&db, &data).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_data_root_and_journal() {
        let temp = tempfile::tempdir().unwrap();
        let (db, data) = open(&temp).await;
        let link = temp.path().join("data-link");
        std::os::unix::fs::symlink(&data, &link).unwrap();
        assert!(guarded_migrate(&db, &link).await.is_err());
        let journal = data.join("migration-journal.json");
        let target = data.join("journal-target");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &journal).unwrap();
        assert!(guarded_migrate(&db, &data).await.is_err());
        fs::remove_file(&journal).unwrap();
        fs::hard_link(&target, &journal).unwrap();
        assert!(guarded_migrate(&db, &data).await.is_err());
    }
}
