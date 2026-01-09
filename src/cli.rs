use crate::database;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Kontor Storage Node CLI")]
pub struct Cli {
    /// Portal API base URL (e.g. https://portal.example.com/api)
    #[arg(long, env = "PORTAL_API_URL", default_value = "http://localhost:8080")]
    pub portal_url: String,

    /// Portal API key used for Bearer authentication
    #[arg(long, env = "PORTAL_API_KEY")]
    pub portal_api_key: String,

    /// Database connection string (default: local SQLite file)
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value_t = database::default_database_url()
    )]
    pub database_url: String,

    /// Directory used to store downloaded files (default: app data dir/files)
    #[arg(long, env = "STORAGE_DIR")]
    pub storage_dir: Option<PathBuf>,

    /// Interval in seconds between portal polling runs
    #[arg(long, env = "PORTAL_POOLING_INTERVAL", default_value_t = 30)]
    pub portal_polling_interval_secs: u64,

    /// Maximum allowed storage for downloaded files (supports M/G/T suffix)
    #[arg(long, env = "STORAGE_CAPACITY")]
    pub storage_capacity: Option<String>,

    /// Maximum number of files to store locally (unlimited by default)
    #[arg(long, env = "STORAGE_MAX_FILES")]
    pub storage_max_files: Option<u64>,

    /// Maximum size of a single file to download/store (supports M/G/T suffix)
    #[arg(long, env = "STORAGE_MAX_FILE_SIZE")]
    pub storage_max_file_size: Option<String>,

    /// Storage method: "local" for local filesystem or "gcs" for Google Cloud Storage
    #[arg(long, env = "STORAGE_METHOD", default_value = "local")]
    pub storage_method: String,

    /// GCS bucket name (required when storage_method is "gcs")
    #[arg(long, env = "STORAGE_GCS_BUCKET_NAME")]
    pub storage_gcs_bucket_name: Option<String>,

    /// Path to GCS service account JSON file (required when storage_method is "gcs")
    #[arg(long, env = "STORAGE_GCS_SERVICE_ACCOUNT_JSON")]
    pub storage_gcs_service_account_json: Option<String>,

    /// Address the server binds to (e.g. 0.0.0.0:8081)
    #[arg(long, env = "SERVER_ADDRESS", default_value = "0.0.0.0:8081")]
    pub server_address: String,

    /// Command to run
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Check connectivity with the Portal API
    Ping,
    /// Run the node background workers
    Run,
}
