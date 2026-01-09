use crate::cli::Cli;
use crate::database::{default_app_dir, default_storage_dir};
use anyhow::{anyhow, Result};
use byte_unit::Byte;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
#[cfg(not(test))]
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

/// Name of the persistent config file stored in app data directory.
const NODE_CONFIG_FILENAME: &str = "node_config.json";

/// Persistent node configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedConfig {
    /// The node ID registered with Horizon Market.
    pub node_id: Option<String>,
}

impl PersistedConfig {
    /// Load the persisted config from the default location.
    /// Returns a default config if the file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(&path)
            .map_err(|e| anyhow!("failed to read config file {}: {e}", path.display()))?;
        serde_json::from_str(&contents)
            .map_err(|e| anyhow!("failed to parse config file {}: {e}", path.display()))
    }

    /// Save the config to the default location.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("failed to create config directory: {e}"))?;
        }
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("failed to serialize config: {e}"))?;
        fs::write(&path, contents)
            .map_err(|e| anyhow!("failed to write config file {}: {e}", path.display()))
    }

    /// Get the path to the config file.
    pub fn config_path() -> Result<PathBuf> {
        let app_dir = default_app_dir()
            .ok_or_else(|| anyhow!("unable to determine application data directory"))?;
        Ok(app_dir.join(NODE_CONFIG_FILENAME))
    }
}

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
        // Try to get node_id from CLI/env first, then fall back to persisted config
        let node_id = if let Some(ref id) = cli.node_id {
            // If provided via CLI/env, persist it for future use
            let mut persisted = PersistedConfig::load().unwrap_or_default();
            if persisted.node_id.as_ref() != Some(id) {
                persisted.node_id = Some(id.clone());
                persisted.save().ok(); // Best effort save
            }
            id.clone()
        } else {
            // Try to load from persisted config
            let persisted = PersistedConfig::load().unwrap_or_default();
            match persisted.node_id {
                Some(id) => id,
                None => {
                    // Prompt user interactively for node_id
                    prompt_for_node_id()?
                }
            }
        };

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

/// Prompts the user interactively to enter their Node ID.
fn prompt_for_node_id() -> Result<String> {
    // In test mode, never prompt interactively
    #[cfg(test)]
    {
        Err(anyhow!(
            "Node ID cannot be empty. Set it via NODE_ID environment variable or --node-id flag."
        ))
    }

    #[cfg(not(test))]
    {
        let stdin = io::stdin();

        // If stdin is not a terminal (e.g., in tests or piped input), we can't prompt interactively
        if !stdin.is_terminal() {
            return Err(anyhow!(
                "Node ID cannot be empty. Set it via NODE_ID environment variable or --node-id flag."
            ));
        }

        println!("NODE_ID is required.");
        println!("You can set it via the NODE_ID environment variable or --node-id flag.");
        println!("If you don't have a Node ID yet, please register as a Storage Node at:");
        println!("https://horizon.market");
        print!("Please enter your Node ID provided by Horizon Market: ");
        io::stdout().flush()?;

        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;

        let node_id = line.trim().to_string();
        if node_id.is_empty() {
            return Err(anyhow!("Node ID cannot be empty"));
        }

        // Persist the node_id for future use
        let mut persisted = PersistedConfig::load().unwrap_or_default();
        persisted.node_id = Some(node_id.clone());
        persisted.save()?;

        Ok(node_id)
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
    use serial_test::serial;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Environment variable used to override the app directory.
    const APP_DIR_ENV_VAR: &str = "KONTOR_APP_DIR";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Returns a unique temporary directory for each test to avoid conflicts.
    fn test_app_dir(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("config")
            .join(format!("{prefix}_{id}"))
    }

    /// Runs a closure with KONTOR_APP_DIR set to a temporary directory.
    /// Restores the original value after the closure completes.
    fn with_temp_app_dir<F, T>(prefix: &str, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let dir = test_app_dir(prefix);
        // Clean up any leftover files from previous test runs
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test app dir");
        let previous = std::env::var(APP_DIR_ENV_VAR).ok();
        std::env::set_var(APP_DIR_ENV_VAR, &dir);
        let result = f();
        match previous {
            Some(val) => std::env::set_var(APP_DIR_ENV_VAR, val),
            None => std::env::remove_var(APP_DIR_ENV_VAR),
        }
        // Clean up the temp directory
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    #[serial]
    fn config_from_cli_clones_fields() {
        with_temp_app_dir("clones_fields", || {
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
        });
    }

    #[test]
    #[serial]
    fn config_from_cli_prompts_for_node_id_when_not_persisted() {
        with_temp_app_dir("prompts_node_id", || {
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

            // In test environment, stdin is empty, so prompt returns an error
            let err = Config::from_cli(&cli).unwrap_err();
            assert!(err.to_string().contains("Node ID cannot be empty"));
        });
    }

    #[test]
    #[serial]
    fn config_from_cli_uses_persisted_node_id() {
        with_temp_app_dir("uses_persisted", || {
            // Save a node_id to the persisted config
            let persisted = PersistedConfig {
                node_id: Some("NODE-persisted".to_string()),
            };
            persisted.save().unwrap();

            let cli = Cli {
                node_id: None, // Not provided via CLI
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

            let config = Config::from_cli(&cli).unwrap();
            assert_eq!(config.node_id, "NODE-persisted");
        });
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
    #[serial]
    fn from_trait_invokes_from_cli() {
        with_temp_app_dir("from_trait", || {
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
        });
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
    #[serial]
    fn config_from_cli_validates_gcs_bucket_required() {
        with_temp_app_dir("gcs_bucket_required", || {
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
        });
    }

    #[test]
    #[serial]
    fn config_from_cli_validates_gcs_service_account_required() {
        with_temp_app_dir("gcs_sa_required", || {
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
        });
    }

    #[test]
    #[serial]
    fn config_from_cli_accepts_valid_gcs_config() {
        with_temp_app_dir("valid_gcs", || {
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
        });
    }
}
