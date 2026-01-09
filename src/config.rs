use crate::cli::Cli;
use crate::database::default_storage_dir;
use anyhow::{anyhow, Result};
use byte_unit::Byte;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Storage backend method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageMethod {
    Local,
    Gcs,
}

impl StorageMethod {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "local" => Ok(StorageMethod::Local),
            "gcs" => Ok(StorageMethod::Gcs),
            other => Err(anyhow!(
                "invalid storage method '{}': expected 'local' or 'gcs'",
                other
            )),
        }
    }
}

impl fmt::Display for StorageMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageMethod::Local => write!(f, "local"),
            StorageMethod::Gcs => write!(f, "gcs"),
        }
    }
}

/// Application configuration derived from CLI arguments and environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub node_id: String,
    pub portal_url: String,
    pub database_url: String,
    pub storage_dir: PathBuf,
    pub portal_polling_interval: Duration,
    pub storage_capacity: Option<u64>,
    pub storage_max_files: Option<u64>,
    pub storage_max_file_size: Option<u64>,
    pub storage_method: StorageMethod,
    pub storage_gcs_bucket_name: Option<String>,
    pub storage_gcs_service_account_json: Option<String>,
    pub server_address: String,
    pub bls_key_path: Option<PathBuf>,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let node_id = cli.node_id.clone().ok_or_else(|| {
            anyhow!(
                "NODE_ID is required.\n\n\
                Please enter your Node ID provided by Horizon Market.\n\
                You can set it via the NODE_ID environment variable or --node-id flag.\n\n\
                If you don't have a Node ID yet, please register as a Storage Node at:\n\
                https://horizon.market"
            )
        })?;

        let storage_capacity = match &cli.storage_capacity {
            Some(raw) => Some(parse_storage_capacity(raw)?),
            None => None,
        };
        let storage_max_file_size = match &cli.storage_max_file_size {
            Some(raw) => Some(parse_storage_capacity(raw)?),
            None => None,
        };

        let storage_method = StorageMethod::from_str(&cli.storage_method)?;

        // Validate GCS configuration when storage method is GCS
        if storage_method == StorageMethod::Gcs {
            if cli.storage_gcs_bucket_name.is_none() {
                return Err(anyhow!(
                    "STORAGE_GCS_BUCKET_NAME is required when STORAGE_METHOD is 'gcs'"
                ));
            }
            if cli.storage_gcs_service_account_json.is_none() {
                return Err(anyhow!(
                    "STORAGE_GCS_SERVICE_ACCOUNT_JSON is required when STORAGE_METHOD is 'gcs'"
                ));
            }
        }

        Ok(Self {
            node_id,
            portal_url: cli.portal_url.clone(),
            database_url: cli.database_url.clone(),
            storage_dir: cli.storage_dir.clone().unwrap_or_else(default_storage_dir),
            portal_polling_interval: Duration::from_secs(cli.portal_polling_interval_secs),
            storage_capacity,
            storage_max_files: cli.storage_max_files,
            storage_max_file_size,
            storage_method,
            storage_gcs_bucket_name: cli.storage_gcs_bucket_name.clone(),
            storage_gcs_service_account_json: cli.storage_gcs_service_account_json.clone(),
            server_address: cli.server_address.clone(),
            bls_key_path: cli.bls_key_path.clone(),
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
            node_id: Some("NODE-abc123".to_string()),
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 42,
            storage_capacity: Some("15GB".into()),
            storage_max_files: Some(10),
            storage_max_file_size: Some("1GB".into()),
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let config = Config::from_cli(&cli).unwrap();

        cli.portal_url.push_str("/extra");
        cli.database_url.push_str("?mode=ro");
        cli.storage_dir = Some(PathBuf::from("/other"));
        cli.storage_capacity = Some("20GB".into());
        cli.storage_max_files = Some(20);

        assert_eq!(config.node_id, "NODE-abc123");
        assert_eq!(config.portal_url, "https://portal.example/api");
        assert_eq!(config.database_url, "sqlite://localhost/mydb");
        assert_eq!(config.storage_dir, PathBuf::from("/tmp/files"));
        assert_eq!(config.portal_polling_interval, Duration::from_secs(42));
        assert_eq!(config.storage_capacity, Some(15_000_000_000));
        assert_eq!(config.storage_max_files, Some(10));
        assert_eq!(config.storage_max_file_size, Some(1_000_000_000));
        assert_eq!(config.storage_method, StorageMethod::Local);
        assert_eq!(config.server_address, "127.0.0.1:0");
    }

    #[test]
    fn config_from_cli_requires_node_id() {
        let cli = Cli {
            node_id: None,
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 10,
            storage_capacity: None,
            storage_max_files: None,
            storage_max_file_size: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("NODE_ID is required"));
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

    #[test]
    fn from_trait_invokes_from_cli() {
        let cli = Cli {
            node_id: Some("NODE-xyz789".to_string()),
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 10,
            storage_capacity: None,
            storage_max_files: None,
            storage_max_file_size: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let config: Config = (&cli).into();
        assert_eq!(config.node_id, "NODE-xyz789");
        assert_eq!(config.portal_url, cli.portal_url);
        assert_eq!(config.database_url, cli.database_url);
        assert_eq!(config.storage_dir, PathBuf::from("/tmp/files"));
        assert_eq!(
            config.portal_polling_interval,
            Duration::from_secs(cli.portal_polling_interval_secs)
        );
    }

    #[test]
    fn storage_method_from_str_parses_local() {
        assert_eq!(
            StorageMethod::from_str("local").unwrap(),
            StorageMethod::Local
        );
        assert_eq!(
            StorageMethod::from_str("LOCAL").unwrap(),
            StorageMethod::Local
        );
    }

    #[test]
    fn storage_method_from_str_parses_gcs() {
        assert_eq!(StorageMethod::from_str("gcs").unwrap(), StorageMethod::Gcs);
        assert_eq!(StorageMethod::from_str("GCS").unwrap(), StorageMethod::Gcs);
    }

    #[test]
    fn storage_method_from_str_rejects_invalid() {
        assert!(StorageMethod::from_str("invalid").is_err());
        assert!(StorageMethod::from_str("").is_err());
    }

    #[test]
    fn config_from_cli_validates_gcs_bucket_required() {
        let cli = Cli {
            node_id: Some("NODE-gcs1".to_string()),
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 10,
            storage_capacity: None,
            storage_max_files: None,
            storage_max_file_size: None,
            storage_method: "gcs".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: Some("/path/to/sa.json".to_string()),
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("STORAGE_GCS_BUCKET_NAME"));
    }

    #[test]
    fn config_from_cli_validates_gcs_service_account_required() {
        let cli = Cli {
            node_id: Some("NODE-gcs2".to_string()),
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 10,
            storage_capacity: None,
            storage_max_files: None,
            storage_max_file_size: None,
            storage_method: "gcs".to_string(),
            storage_gcs_bucket_name: Some("my-bucket".to_string()),
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("STORAGE_GCS_SERVICE_ACCOUNT_JSON"));
    }

    #[test]
    fn config_from_cli_accepts_valid_gcs_config() {
        let cli = Cli {
            node_id: Some("NODE-gcs3".to_string()),
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 10,
            storage_capacity: None,
            storage_max_files: None,
            storage_max_file_size: None,
            storage_method: "gcs".to_string(),
            storage_gcs_bucket_name: Some("my-bucket".to_string()),
            storage_gcs_service_account_json: Some("/path/to/sa.json".to_string()),
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let config = Config::from_cli(&cli).unwrap();
        assert_eq!(config.storage_method, StorageMethod::Gcs);
        assert_eq!(
            config.storage_gcs_bucket_name,
            Some("my-bucket".to_string())
        );
        assert_eq!(
            config.storage_gcs_service_account_json,
            Some("/path/to/sa.json".to_string())
        );
    }
}
