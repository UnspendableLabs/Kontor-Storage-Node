use crate::cli::Cli;
use crate::database::default_storage_dir;
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
}

impl From<&Cli> for Config {
    fn from(cli: &Cli) -> Self {
        Self {
            portal_url: cli.portal_url.clone(),
            portal_api_key: cli.portal_api_key.clone(),
            database_url: cli.database_url.clone(),
            storage_dir: cli.storage_dir.clone().unwrap_or_else(default_storage_dir),
            portal_polling_interval: Duration::from_secs(cli.portal_polling_interval_secs),
        }
    }
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
            command: Commands::Ping,
        };

        let config = Config::from(&cli);

        cli.portal_url.push_str("/extra");
        cli.portal_api_key.push_str("123");
        cli.database_url.push_str("?mode=ro");
        cli.storage_dir = Some(PathBuf::from("/other"));

        assert_eq!(config.portal_url, "https://portal.example/api");
        assert_eq!(config.portal_api_key, "secret");
        assert_eq!(config.database_url, "sqlite://localhost/mydb");
        assert_eq!(config.storage_dir, PathBuf::from("/tmp/files"));
        assert_eq!(config.portal_polling_interval, Duration::from_secs(42));
    }
}
