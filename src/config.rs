use crate::cli::Cli;
use crate::database::default_storage_dir;
use anyhow::{anyhow, Result};
use byte_unit::Byte;
use std::path::PathBuf;
use std::time::Duration;

/// Application configuration derived from CLI arguments and environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub portal_url: String,
    pub portal_api_key: String,
    pub database_url: String,
    pub storage_dir: PathBuf,
    pub portal_polling_interval: Duration,
    pub storage_capacity: Option<u64>,
    pub storage_max_files: Option<u64>,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let storage_capacity = match &cli.storage_capacity {
            Some(raw) => Some(parse_storage_capacity(raw)?),
            None => None,
        };

        Ok(Self {
            portal_url: cli.portal_url.clone(),
            portal_api_key: cli.portal_api_key.clone(),
            database_url: cli.database_url.clone(),
            storage_dir: cli.storage_dir.clone().unwrap_or_else(default_storage_dir),
            portal_polling_interval: Duration::from_secs(cli.portal_polling_interval_secs),
            storage_capacity,
            storage_max_files: cli.storage_max_files,
        })
    }
}

impl From<&Cli> for Config {
    fn from(cli: &Cli) -> Self {
        Config::from_cli(cli).expect("invalid CLI values")
    }
}

fn parse_storage_capacity(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("storage capacity cannot be empty"));
    }

    let bytes = Byte::from_str(trimmed)
        .map_err(|err| anyhow!("invalid storage capacity '{trimmed}': {err}"))?
        .get_bytes();

    let bytes: u64 = bytes
        .try_into()
        .map_err(|_| anyhow!("storage capacity '{trimmed}' exceeds u64"))?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};

    #[test]
    fn config_from_cli_clones_fields() {
        let mut cli = Cli {
            portal_url: "https://portal.example/api".to_string(),
            portal_api_key: "secret".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 42,
            storage_capacity: Some("15GB".into()),
            storage_max_files: Some(10),
            command: Commands::Ping,
        };

        let config = Config::from_cli(&cli).unwrap();

        cli.portal_url.push_str("/extra");
        cli.portal_api_key.push_str("123");
        cli.database_url.push_str("?mode=ro");
        cli.storage_dir = Some(PathBuf::from("/other"));
        cli.storage_capacity = Some("20GB".into());
        cli.storage_max_files = Some(20);

        assert_eq!(config.portal_url, "https://portal.example/api");
        assert_eq!(config.portal_api_key, "secret");
        assert_eq!(config.database_url, "sqlite://localhost/mydb");
        assert_eq!(config.storage_dir, PathBuf::from("/tmp/files"));
        assert_eq!(config.portal_polling_interval, Duration::from_secs(42));
        assert_eq!(config.storage_capacity, Some(15_000_000_000));
        assert_eq!(config.storage_max_files, Some(10));
    }

    #[test]
    fn parse_storage_capacity_supports_units() {
        assert_eq!(parse_storage_capacity("10M").unwrap(), 10_000_000);
        assert_eq!(parse_storage_capacity("2GB").unwrap(), 2_000_000_000);
        assert_eq!(parse_storage_capacity("1 tb").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_storage_capacity("1GiB").unwrap(), 1_073_741_824);
    }

    #[test]
    fn parse_storage_capacity_rejects_invalid_values() {
        assert!(parse_storage_capacity("").is_err());
        assert!(parse_storage_capacity("abc").is_err());
        assert!(parse_storage_capacity("10 XB").is_err());
    }
}
