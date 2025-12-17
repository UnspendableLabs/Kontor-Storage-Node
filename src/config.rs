use crate::cli::Cli;
use crate::database::default_storage_dir;
use std::path::PathBuf;

/// Application configuration derived from CLI arguments and environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub portal_url: String,
    pub database_url: String,
    pub storage_dir: PathBuf,
}

impl From<&Cli> for Config {
    fn from(cli: &Cli) -> Self {
        Self {
            portal_url: cli.portal_url.clone(),
            database_url: cli.database_url.clone(),
            storage_dir: cli.storage_dir.clone().unwrap_or_else(default_storage_dir),
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
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            command: Commands::Ping,
        };

        let config = Config::from(&cli);

        cli.portal_url.push_str("/extra");
        cli.database_url.push_str("?mode=ro");
        cli.storage_dir = Some(PathBuf::from("/other"));

        assert_eq!(config.portal_url, "https://portal.example/api");
        assert_eq!(config.database_url, "sqlite://localhost/mydb");
        assert_eq!(config.storage_dir, PathBuf::from("/tmp/files"));
    }
}
