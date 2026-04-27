use anyhow::{Context, Result};
use std::path::Path;

/// Ensures the SQLite database file exists, creating it (and parent directories) if needed.
/// No-op for non-SQLite URLs and for `sqlite::memory:` (which lives in RAM).
///
/// This used to also return a `bool` signalling whether the file was newly created so the
/// caller could decide to run migrations. That signal was always discarded since the
/// caller now runs migrations unconditionally to handle schema upgrades on existing
/// databases, so the return type was simplified to `Result<()>`.
pub(crate) fn prepare_sqlite(database_url: &str) -> Result<()> {
    if !is_sqlite_url(database_url) {
        return Ok(());
    }

    let Some(file_path) = extract_sqlite_file_path(database_url) else {
        return Ok(());
    };

    if file_path == ":memory:" {
        return Ok(());
    }

    ensure_sqlite_file_exists(&file_path)?;
    Ok(())
}

fn is_sqlite_url(url: &str) -> bool {
    url.starts_with("sqlite:")
}

fn extract_sqlite_file_path(url: &str) -> Option<String> {
    url.strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .map(ToString::to_string)
}

fn ensure_sqlite_file_exists(file_path: &str) -> Result<()> {
    let path = Path::new(file_path);

    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create directory {} for SQLite database",
                parent.display()
            )
        })?;
    }

    std::fs::File::create(path).with_context(|| {
        format!(
            "failed to create SQLite database file at {}",
            path.display()
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutils::unique_test_path;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn cleanup_path(path: &Path) {
        if path.is_file() {
            fs::remove_file(path).ok();
        } else if path.is_dir() {
            fs::remove_dir_all(path).ok();
        }
    }

    #[test]
    fn is_sqlite_url_and_extract_sqlite_file_path() {
        assert!(is_sqlite_url("sqlite://tmp/test.db"));
        assert!(!is_sqlite_url("postgres://tmp/test.db"));

        assert_eq!(
            extract_sqlite_file_path("sqlite:///tmp/test.db"),
            Some("/tmp/test.db".to_string())
        );
        assert_eq!(
            extract_sqlite_file_path("sqlite:relative/test.db"),
            Some("relative/test.db".to_string())
        );
        assert_eq!(extract_sqlite_file_path("postgres:///tmp/test.db"), None);
    }

    #[test]
    fn prepare_sqlite_succeeds_for_non_sqlite_url() {
        assert!(prepare_sqlite("postgres://db").is_ok());
    }

    #[test]
    fn prepare_sqlite_succeeds_for_memory_url() {
        assert!(prepare_sqlite("sqlite::memory:").is_ok());
    }

    #[test]
    fn ensure_sqlite_file_exists_succeeds_when_file_is_present() {
        let path = unique_test_path("existing_file").with_extension("sqlite");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::File::create(&path).unwrap();

        ensure_sqlite_file_exists(path.to_str().unwrap()).unwrap();
        assert!(path.exists(), "file should remain after no-op call");
        cleanup_path(&path);
    }

    #[test]
    fn prepare_sqlite_creates_file_when_missing() {
        let db_path = unique_test_path("create_and_signal").join("db.sqlite");
        let db_url = format!("sqlite://{}", db_path.display());

        if let Some(parent) = db_path.parent() {
            fs::remove_dir_all(parent).ok();
        }

        prepare_sqlite(&db_url).unwrap();
        assert!(db_path.exists());
        // Calling again when the file already exists must remain a no-op.
        prepare_sqlite(&db_url).unwrap();
        assert!(db_path.exists());

        cleanup_path(db_path.parent().unwrap());
    }

    #[test]
    fn ensure_sqlite_file_exists_errors_when_parent_is_file() {
        let parent_file = unique_test_path("parent_file");
        if let Some(parent) = parent_file.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&parent_file, b"not a directory").unwrap();
        let target = parent_file.join("child").with_extension("sqlite");

        let err = ensure_sqlite_file_exists(target.to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("failed to create directory"),
            "unexpected error: {err}"
        );

        cleanup_path(&parent_file);
    }

    #[test]
    fn ensure_sqlite_file_exists_errors_when_parent_is_read_only() {
        let dir_path = unique_test_path("parent_read_only");
        if let Some(parent) = dir_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::create_dir_all(&dir_path).unwrap();
        let file_path = dir_path.join("db.sqlite");
        fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o555)).unwrap();

        let err = ensure_sqlite_file_exists(file_path.to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("failed to create SQLite database file"),
            "unexpected error: {err}"
        );

        fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o755)).ok();
        cleanup_path(&dir_path);
    }
}
