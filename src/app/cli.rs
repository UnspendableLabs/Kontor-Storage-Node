use crate::database;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Migrate the legacy `PORTAL_POOLING_INTERVAL` env var (typo) to the corrected
/// `PORTAL_POLLING_INTERVAL` if only the legacy one is set. Emits a deprecation
/// warning so operators can update their configuration.
///
/// Must be called BEFORE [`Cli::parse`] so clap picks up the migrated value.
pub fn migrate_legacy_env_vars() {
    if std::env::var("PORTAL_POLLING_INTERVAL").is_err() {
        if let Ok(value) = std::env::var("PORTAL_POOLING_INTERVAL") {
            eprintln!(
                "warning: PORTAL_POOLING_INTERVAL is deprecated (typo), \
                 use PORTAL_POLLING_INTERVAL"
            );
            std::env::set_var("PORTAL_POLLING_INTERVAL", value);
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Kontor Storage Node CLI")]
pub struct Cli {
    /// Portal API base URL (e.g. <https://portal.example.com/api>).
    ///
    /// Defaults to the develop Portal, so a node with no configuration at all
    /// has something to register against — the point of the zero-config path.
    /// A production deployment sets this.
    #[arg(
        long,
        env = "PORTAL_API_URL",
        default_value = "https://portal-application-develop.up.railway.app"
    )]
    pub portal_url: String,

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

    /// Application data directory: the keystore, the admin credential and the
    /// SQLite database live here (default: platform data dir, `/data` in Docker).
    ///
    /// This is the one directory that must survive a restart for the node to
    /// come back unattended.
    #[arg(long, env = "KONTOR_APP_DIR")]
    pub app_dir: Option<PathBuf>,

    /// Interval in seconds between portal polling runs
    #[arg(long, env = "PORTAL_POLLING_INTERVAL", default_value_t = 30)]
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

    /// Path to GCS service account JSON file, or inline JSON (same as Portal: `[n]` = newline in env)
    #[arg(long, env = "STORAGE_GCS_SERVICE_ACCOUNT_JSON")]
    pub storage_gcs_service_account_json: Option<String>,

    /// Address the server binds to (e.g. 0.0.0.0:8081)
    #[arg(long, env = "SERVER_ADDRESS", default_value = "0.0.0.0:8081")]
    pub server_address: String,

    /// Public URL where this node is reachable for file downloads (e.g. <https://node1.example.com>)
    #[arg(long, env = "PUBLIC_URL", default_value = "http://localhost:8081")]
    pub public_url: String,

    /// Path to the BLS key file (default: app data dir/bls_key.enc)
    /// For non-interactive mode, also set BLS_PASSWORD environment variable.
    #[arg(long, env = "BLS_KEY_PATH")]
    pub bls_key_path: Option<PathBuf>,

    /// Password guarding the operator UI at `/admin`.
    ///
    /// Unset (the default) disables the UI: the page still renders, but login
    /// answers 503 so there is nothing to guess. When set it must be at least
    /// [`crate::app::config::MIN_ADMIN_PASSWORD_LEN`] characters — it is the
    /// only credential standing between the internet and a database wipe.
    #[arg(long, env = "ADMIN_PASSWORD")]
    pub admin_password: Option<String>,

    /// Kontor address of the filestorage contract this node signs operations
    /// against. MUST match the Portal's own `KONTOR_CONTRACT_ADDRESS`: the
    /// contract address is part of the signed `Inst`, so a mismatch makes every
    /// join/proof signature fail the Portal's verification.
    #[arg(
        long,
        env = "KONTOR_CONTRACT_ADDRESS",
        default_value = "filestorage_0_0"
    )]
    pub kontor_contract_address: String,

    /// Kontor address of the staking contract this node bonds its collateral
    /// in. MUST match the Portal's own `KONTOR_STAKING_CONTRACT_ADDRESS`, for
    /// the same reason as the filestorage address: it is inside every signed
    /// `add-stake`, `begin-unstake` and `withdraw-stake`.
    #[arg(
        long,
        env = "KONTOR_STAKING_CONTRACT_ADDRESS",
        default_value = "staking_0_0"
    )]
    pub kontor_staking_contract_address: String,

    /// Bond spare KOR as collateral and claim storage rewards automatically.
    ///
    /// On by default: Kontor refuses every join without enough unreserved
    /// stake, so a node that does not stake stores nothing new. Off, the node
    /// signs no stake or claim op on its own, and joins only what a bond
    /// funded by hand covers.
    #[arg(
        long,
        env = "KONTOR_STORAGE_AUTO_STAKE",
        default_value_t = true,
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub auto_stake: bool,

    /// KOR kept liquid to pay gas for joins and proofs; auto-stake never bonds
    /// it. Decimal, e.g. `5` or `2.5`.
    #[arg(long, env = "KONTOR_STORAGE_GAS_RESERVE_KOR", default_value = "5")]
    pub gas_reserve_kor: String,

    /// Cap on the total bonded stake. Unset (the default) bonds everything
    /// above the gas reserve.
    #[arg(long, env = "KONTOR_STORAGE_STAKE_TARGET_KOR")]
    pub stake_target_kor: Option<String>,

    /// KOR requested from the Portal faucet when the node starts with an empty
    /// balance. The Portal caps it (`PORTAL_FAUCET_MAX_AMOUNT_KOR`).
    #[arg(long, env = "KONTOR_STORAGE_FAUCET_AMOUNT_KOR", default_value = "1000")]
    pub faucet_amount_kor: String,

    /// Claim storage rewards once at least this much KOR is claimable.
    #[arg(long, env = "KONTOR_STORAGE_CLAIM_THRESHOLD_KOR", default_value = "1")]
    pub claim_threshold_kor: String,

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
    /// Apply, roll back or inspect database migrations
    ///
    /// A SQLite node migrates itself the moment it connects, so this exists
    /// for the databases that do not — Postgres and MySQL — and for operators
    /// who would rather run the schema change before the deploy than during it.
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateAction {
    /// Apply every pending migration
    Up,
    /// Roll back the most recently applied migrations
    Down {
        /// How many migrations to roll back
        #[arg(short = 'n', long = "num", default_value_t = 1)]
        num: u32,
    },
    /// List every migration and whether it has been applied
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &str = "PORTAL_POOLING_INTERVAL";
    const CORRECTED: &str = "PORTAL_POLLING_INTERVAL";

    /// Snapshot of both env vars so each test can restore the prior process state.
    /// Mirrors the guard pattern used in `database/client.rs` serial tests.
    struct EnvGuard {
        legacy_prev: Option<String>,
        corrected_prev: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            let guard = Self {
                legacy_prev: std::env::var(LEGACY).ok(),
                corrected_prev: std::env::var(CORRECTED).ok(),
            };
            std::env::remove_var(LEGACY);
            std::env::remove_var(CORRECTED);
            guard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.legacy_prev.take() {
                Some(val) => std::env::set_var(LEGACY, val),
                None => std::env::remove_var(LEGACY),
            }
            match self.corrected_prev.take() {
                Some(val) => std::env::set_var(CORRECTED, val),
                None => std::env::remove_var(CORRECTED),
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn migrate_legacy_env_vars_copies_old_to_new_when_only_old_is_set() {
        let _guard = EnvGuard::capture();
        std::env::set_var(LEGACY, "45");

        migrate_legacy_env_vars();

        assert_eq!(std::env::var(CORRECTED).ok(), Some("45".to_string()));
    }

    #[test]
    #[serial_test::serial]
    fn migrate_legacy_env_vars_preserves_new_when_both_are_set() {
        let _guard = EnvGuard::capture();
        std::env::set_var(LEGACY, "45");
        std::env::set_var(CORRECTED, "60");

        migrate_legacy_env_vars();

        assert_eq!(std::env::var(CORRECTED).ok(), Some("60".to_string()));
    }

    #[test]
    #[serial_test::serial]
    fn migrate_legacy_env_vars_is_noop_when_neither_is_set() {
        let _guard = EnvGuard::capture();

        migrate_legacy_env_vars();

        assert!(std::env::var(LEGACY).is_err());
        assert!(std::env::var(CORRECTED).is_err());
    }

    /// Auto-stake is on unless switched off, and the switch takes the usual
    /// spellings of a boolean environment variable.
    #[test]
    #[serial_test::serial]
    fn auto_stake_defaults_on_and_accepts_boolish_values() {
        let parse = |args: &[&str]| {
            let mut argv = vec!["kontor-storage-node"];
            argv.extend_from_slice(args);
            argv.push("ping");
            Cli::try_parse_from(argv).unwrap()
        };
        if std::env::var("KONTOR_STORAGE_AUTO_STAKE").is_err() {
            assert!(parse(&[]).auto_stake);
        }
        for off in ["false", "0", "no", "off"] {
            assert!(!parse(&["--auto-stake", off]).auto_stake, "{off}");
        }
        for on in ["true", "1", "yes", "on"] {
            assert!(parse(&["--auto-stake", on]).auto_stake, "{on}");
        }
    }
}
