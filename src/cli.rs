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
