use anyhow::{Context, Result};
use std::path::Path;

/// Ensures SQLite databases have a file created and signals whether migrations should run.
pub(crate) fn prepare_sqlite(database_url: &str) -> Result<bool> {
    if !is_sqlite_url(database_url) {
        return Ok(false);
    }

    let Some(file_path) = extract_sqlite_file_path(database_url) else {
        return Ok(false);
    };

    if file_path == ":memory:" {
        return Ok(true);
    }

    let file_existed = ensure_sqlite_file_exists(&file_path)?;
    Ok(!file_existed)
}

fn is_sqlite_url(url: &str) -> bool {
    url.starts_with("sqlite:")
}

fn extract_sqlite_file_path(url: &str) -> Option<String> {
    url.strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .map(ToString::to_string)
}

fn ensure_sqlite_file_exists(file_path: &str) -> Result<bool> {
    let path = Path::new(file_path);

    if path.exists() {
        return Ok(true);
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

    Ok(false)
}
