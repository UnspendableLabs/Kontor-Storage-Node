use crate::app::cli::Cli;
use crate::app::tasks::stake::{StakePolicy, MIN_GAS_RESERVE};
use crate::clients::kor::Kor;
use crate::database::{default_app_dir, default_storage_dir};
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
        if s.eq_ignore_ascii_case("local") {
            Ok(StorageMethod::Local)
        } else if s.eq_ignore_ascii_case("gcs") {
            Ok(StorageMethod::Gcs)
        } else {
            Err(anyhow!(
                "invalid storage method '{s}': expected 'local' or 'gcs'"
            ))
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

/// Minimum length of `ADMIN_PASSWORD` when it is set.
///
/// Unlike a generated token this is typed by a human, so the floor is length
/// rather than entropy. It is enforced at startup because the password is the
/// only credential guarding `/admin`, which can wipe the node's database.
pub const MIN_ADMIN_PASSWORD_LEN: usize = 16;

/// Password guarding the operator UI, kept out of `Debug` output.
///
/// [`Config`] derives `Debug` and is cheap to interpolate into a log line; a
/// bare `String` here would eventually end up in one.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminPassword(String);

impl AdminPassword {
    /// Builds the password from the CLI/env value. Absent and blank are the
    /// same thing — both mean "no admin UI".
    pub fn new(raw: Option<&str>) -> Self {
        Self(
            raw.filter(|value| !value.trim().is_empty())
                .unwrap_or("")
                .to_string(),
        )
    }

    /// True when no password is configured, i.e. the admin UI is disabled.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The password itself. Only the login comparison should call this.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdminPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_empty() {
            "<empty>"
        } else {
            "<redacted>"
        })
    }
}

/// Application configuration derived from CLI arguments and environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub portal_url: String,
    pub database_url: String,
    pub storage_dir: PathBuf,
    /// Where the keystore, the admin credential and the database live. Resolved
    /// once here so nothing downstream has to re-read `KONTOR_APP_DIR` and
    /// disagree about the answer.
    pub app_dir: PathBuf,
    pub portal_polling_interval: Duration,
    pub storage_capacity: Option<u64>,
    pub storage_max_files: Option<u64>,
    pub storage_max_file_size: Option<u64>,
    pub storage_method: StorageMethod,
    pub storage_gcs_bucket_name: Option<String>,
    pub storage_gcs_service_account_json: Option<String>,
    pub server_address: String,
    pub public_url: String,
    pub bls_key_path: Option<PathBuf>,
    /// Password for the operator UI at `/admin`. Empty disables the UI.
    pub admin_password: AdminPassword,
    /// Kontor address of the filestorage contract, mirroring the Portal's
    /// `KONTOR_CONTRACT_ADDRESS`. Part of every signed `Inst`, so both sides
    /// must agree or signature verification fails.
    pub kontor_contract_address: String,
    /// Kontor address of the staking contract, mirroring the Portal's
    /// `KONTOR_STAKING_CONTRACT_ADDRESS`; signed into every stake op.
    pub kontor_staking_contract_address: String,
    /// How the node keeps its collateral bonded.
    pub stake_policy: StakePolicy,
    /// KOR asked of the faucet when the balance is empty.
    pub faucet_amount: Kor,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let storage_capacity = cli
            .storage_capacity
            .as_deref()
            .map(|s| parse_storage_capacity(s, "STORAGE_CAPACITY"))
            .transpose()?;
        let storage_max_file_size = cli
            .storage_max_file_size
            .as_deref()
            .map(|s| parse_storage_capacity(s, "STORAGE_MAX_FILE_SIZE"))
            .transpose()?;

        let storage_method = StorageMethod::from_str(&cli.storage_method)?;

        let kontor_contract_address =
            parse_contract_address(&cli.kontor_contract_address, "KONTOR_CONTRACT_ADDRESS")?;
        let kontor_staking_contract_address = parse_contract_address(
            &cli.kontor_staking_contract_address,
            "KONTOR_STAKING_CONTRACT_ADDRESS",
        )?;

        let stake_policy = StakePolicy {
            auto_stake: cli.auto_stake,
            gas_reserve: parse_gas_reserve(&cli.gas_reserve_kor)?,
            stake_target: cli
                .stake_target_kor
                .as_deref()
                .filter(|raw| !raw.trim().is_empty())
                .map(|raw| parse_kor_positive(raw, "KONTOR_STORAGE_STAKE_TARGET_KOR"))
                .transpose()?,
            claim_threshold: parse_kor_positive(
                &cli.claim_threshold_kor,
                "KONTOR_STORAGE_CLAIM_THRESHOLD_KOR",
            )?,
            unknown_collateral_estimate: parse_kor_positive(
                &cli.unknown_collateral_estimate_kor,
                "KONTOR_STORAGE_UNKNOWN_COLLATERAL_ESTIMATE_KOR",
            )?,
        };
        let faucet_amount =
            parse_kor_positive(&cli.faucet_amount_kor, "KONTOR_STORAGE_FAUCET_AMOUNT_KOR")?;

        // Every secret this node keeps at rest is written here, so a platform
        // with no data directory and no override has nowhere to be a node from.
        // Better to say that by name than to fail later on a path that was
        // silently built from the current working directory.
        let app_dir = cli
            .app_dir
            .clone()
            .or_else(default_app_dir)
            .ok_or_else(|| {
                anyhow!(
                    "no application data directory could be determined. \
                     Set KONTOR_APP_DIR to a directory that survives restarts — \
                     it holds this node's sealed key and its database."
                )
            })?;

        let admin_password = AdminPassword::new(cli.admin_password.as_deref());
        if !admin_password.is_empty()
            && admin_password.expose().chars().count() < MIN_ADMIN_PASSWORD_LEN
        {
            return Err(anyhow!(
                "ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LEN} characters. \
                 It is the only credential guarding the /admin UI, which can wipe this \
                 node's database. Leave it unset to disable the admin UI entirely."
            ));
        }

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
            portal_url: cli.portal_url.clone(),
            database_url: cli.database_url.clone(),
            storage_dir: cli.storage_dir.clone().unwrap_or_else(default_storage_dir),
            app_dir,
            portal_polling_interval: Duration::from_secs(cli.portal_polling_interval_secs),
            storage_capacity,
            storage_max_files: cli.storage_max_files,
            storage_max_file_size,
            storage_method,
            storage_gcs_bucket_name: cli.storage_gcs_bucket_name.clone(),
            storage_gcs_service_account_json: cli.storage_gcs_service_account_json.clone(),
            server_address: cli.server_address.clone(),
            public_url: cli.public_url.clone(),
            bls_key_path: cli.bls_key_path.clone(),
            admin_password,
            kontor_contract_address,
            kontor_staking_contract_address,
            stake_policy,
            faucet_amount,
        })
    }
}

/// Check that `raw` is a Kontor contract address in its canonical spelling,
/// `name_height_txindex`, and return it trimmed.
///
/// The address is signed into every op. The Portal parses it as Kontor's
/// `ContractAddress` (`core/macros/src/contract_address.rs` at 80913826) and
/// renders it back as `{name}_{height}_{tx_index}` before rebuilding the
/// message it verifies the signature against; a spelling that parses but
/// renders differently — `staking_00_0`, `staking_+1_0`, `staking_0_01` —
/// signs a different message, and every op fails `BLS_VERIFY_FAILED`. So the
/// value must be what Kontor would render, and only that: exactly three
/// `_`-separated parts, a height (`u64`) and a tx index (`u32`) written as
/// plain decimals, and a name Kontor takes as it is. Kontor normalises
/// nothing in the name — any text without `_` round-trips — so no charset is
/// imposed on it beyond what cannot be meant in an address: an empty name,
/// whitespace or a control character.
///
/// # Errors
/// With a message naming `variable`, if the value is not such an address.
pub fn parse_contract_address(raw: &str, variable: &str) -> Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(anyhow!("{variable} cannot be empty"));
    }
    let invalid = |why: &str| {
        anyhow!(
            "{variable} must be a Kontor contract address spelt as name_height_txindex, \
             like staking_0_0 (got {value:?}): {why}"
        )
    };
    let parts: Vec<&str> = value.split('_').collect();
    let [name, height, tx_index] = parts[..] else {
        return Err(invalid("expected 3 parts separated by '_'"));
    };
    if name.is_empty() {
        return Err(invalid("the name is empty"));
    }
    if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(
            "the name contains whitespace or a control character",
        ));
    }
    if height.parse::<u64>().ok().map(|h| h.to_string()).as_deref() != Some(height) {
        return Err(invalid(
            "the height must be a plain decimal that fits u64, as Kontor renders it",
        ));
    }
    if tx_index
        .parse::<u32>()
        .ok()
        .map(|i| i.to_string())
        .as_deref()
        != Some(tx_index)
    {
        return Err(invalid(
            "the tx index must be a plain decimal that fits u32, as Kontor renders it",
        ));
    }
    Ok(value.to_string())
}

impl TryFrom<&Cli> for Config {
    type Error = anyhow::Error;

    fn try_from(cli: &Cli) -> Result<Self> {
        Config::from_cli(cli)
    }
}

/// A KOR amount from the environment: an exact decimal, so `0.1` is `0.1`.
fn parse_kor(raw: &str, field_name: &str) -> Result<Kor> {
    Kor::parse(raw).map_err(|err| anyhow!("invalid {field_name}: {err}"))
}

/// [`parse_kor`], refusing a reserve below [`MIN_GAS_RESERVE`]: Kontor holds an
/// op's gas from the balance before running it, so with less kept back every
/// `add-stake` of "everything above the reserve" fails on chain.
fn parse_gas_reserve(raw: &str) -> Result<Kor> {
    let reserve = parse_kor(raw, "KONTOR_STORAGE_GAS_RESERVE_KOR")?;
    if reserve < MIN_GAS_RESERVE {
        return Err(anyhow!(
            "invalid KONTOR_STORAGE_GAS_RESERVE_KOR: {reserve} KOR is below the minimum of \
             {MIN_GAS_RESERVE} KOR. Kontor holds an op's gas from the balance before running \
             it, so a smaller reserve makes every add-stake of the rest fail; and the node \
             pays its own proofs out of it (5 KOR by default)"
        ));
    }
    Ok(reserve)
}

/// [`parse_kor`] for amounts where zero makes no sense: a zero claim threshold
/// would claim dust every hour, a zero target would stake nothing while saying
/// it stakes, and a zero faucet request is refused by the Portal.
fn parse_kor_positive(raw: &str, field_name: &str) -> Result<Kor> {
    Kor::parse_positive(raw).map_err(|err| anyhow!("invalid {field_name}: {err}"))
}

fn parse_storage_capacity(raw: &str, field_name: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{field_name} cannot be empty"));
    }

    let bytes = Byte::from_str(trimmed)
        .map_err(|err| anyhow!("invalid {field_name} '{trimmed}': {err}"))?
        .get_bytes();

    let bytes: u64 = bytes
        .try_into()
        .map_err(|_| anyhow!("{field_name} '{trimmed}' exceeds u64"))?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::cli::{Cli, Commands};

    fn make_cli() -> Cli {
        Cli {
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            app_dir: None,
            storage_dir: Some(PathBuf::from("/tmp/files")),
            portal_polling_interval_secs: 10,
            storage_capacity: None,
            storage_max_files: None,
            storage_max_file_size: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: None,
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
            kontor_staking_contract_address: "staking_0_0".to_string(),
            auto_stake: true,
            gas_reserve_kor: "5".to_string(),
            stake_target_kor: None,
            faucet_amount_kor: "1000".to_string(),
            claim_threshold_kor: "1".to_string(),
            unknown_collateral_estimate_kor: "10".to_string(),
            command: Commands::Ping,
        }
    }

    #[test]
    fn config_from_cli_clones_fields() {
        let mut cli = Cli {
            storage_capacity: Some("15GB".into()),
            storage_max_files: Some(10),
            storage_max_file_size: Some("1GB".into()),
            portal_polling_interval_secs: 42,
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();

        cli.portal_url.push_str("/extra");
        cli.database_url.push_str("?mode=ro");
        cli.storage_dir = Some(PathBuf::from("/other"));
        cli.storage_capacity = Some("20GB".into());
        cli.storage_max_files = Some(20);

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
    fn parse_storage_capacity_supports_units() {
        assert_eq!(
            parse_storage_capacity("10M", "STORAGE_CAPACITY").unwrap(),
            10_000_000
        );
        assert_eq!(
            parse_storage_capacity("2GB", "STORAGE_CAPACITY").unwrap(),
            2_000_000_000
        );
        assert_eq!(
            parse_storage_capacity("1 tb", "STORAGE_CAPACITY").unwrap(),
            1_000_000_000_000
        );
        assert_eq!(
            parse_storage_capacity("1GiB", "STORAGE_CAPACITY").unwrap(),
            1_073_741_824
        );
    }

    #[test]
    fn parse_storage_capacity_rejects_invalid_values() {
        assert!(parse_storage_capacity("", "STORAGE_CAPACITY").is_err());
        assert!(parse_storage_capacity("abc", "STORAGE_CAPACITY").is_err());
        assert!(parse_storage_capacity("10 XB", "STORAGE_CAPACITY").is_err());
    }

    #[test]
    fn try_from_trait_invokes_from_cli() {
        let cli = make_cli();

        let config: Config = Config::try_from(&cli).unwrap();
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
            storage_method: "gcs".to_string(),
            storage_gcs_service_account_json: Some("/path/to/sa.json".to_string()),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("STORAGE_GCS_BUCKET_NAME"));
    }

    #[test]
    fn config_from_cli_validates_gcs_service_account_required() {
        let cli = Cli {
            storage_method: "gcs".to_string(),
            storage_gcs_bucket_name: Some("my-bucket".to_string()),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("STORAGE_GCS_SERVICE_ACCOUNT_JSON"));
    }

    #[test]
    fn config_from_cli_accepts_valid_gcs_config() {
        let cli = Cli {
            storage_method: "gcs".to_string(),
            storage_gcs_bucket_name: Some("my-bucket".to_string()),
            storage_gcs_service_account_json: Some("/path/to/sa.json".to_string()),
            ..make_cli()
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

    #[test]
    fn storage_method_display_local() {
        assert_eq!(StorageMethod::Local.to_string(), "local");
    }

    #[test]
    fn storage_method_display_gcs() {
        assert_eq!(StorageMethod::Gcs.to_string(), "gcs");
    }

    #[test]
    fn config_from_cli_uses_default_storage_dir_when_none() {
        let cli = Cli {
            app_dir: None,
            storage_dir: None,
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();
        assert_eq!(config.storage_dir, crate::database::default_storage_dir());
    }

    #[test]
    fn config_from_cli_clones_bls_key_path() {
        let cli = Cli {
            bls_key_path: Some(PathBuf::from("/path/to/bls_key.enc")),
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();
        assert_eq!(
            config.bls_key_path,
            Some(PathBuf::from("/path/to/bls_key.enc"))
        );
    }

    #[test]
    fn parse_storage_capacity_supports_pure_bytes() {
        assert_eq!(
            parse_storage_capacity("1024", "STORAGE_CAPACITY").unwrap(),
            1024
        );
        assert_eq!(
            parse_storage_capacity("  500  ", "STORAGE_CAPACITY").unwrap(),
            500
        );
    }

    #[test]
    fn config_from_cli_rejects_invalid_storage_method() {
        let cli = Cli {
            storage_method: "invalid_method".to_string(),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("invalid storage method"));
    }

    #[test]
    fn config_from_cli_rejects_invalid_storage_capacity() {
        let cli = Cli {
            storage_capacity: Some("not_a_number".to_string()),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("invalid STORAGE_CAPACITY"));
    }

    #[test]
    fn config_from_cli_rejects_invalid_storage_max_file_size() {
        let cli = Cli {
            storage_max_file_size: Some("bad_value".to_string()),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("invalid STORAGE_MAX_FILE_SIZE"));
    }

    /// An empty contract address would be signed into every op and rejected by
    /// the Portal on every request, so fail at startup with the variable's name
    /// rather than at the first join.
    #[test]
    fn config_from_cli_rejects_empty_contract_address() {
        let cli = Cli {
            kontor_contract_address: "   ".to_string(),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("KONTOR_CONTRACT_ADDRESS"));
    }

    /// The Portal re-renders the address it parses before verifying the
    /// signature, so only the canonical spelling signs the right message. A
    /// non-canonical one fails every op with BLS_VERIFY_FAILED, which is a
    /// worse place to find out than startup.
    #[test]
    fn contract_addresses_must_be_canonical() {
        for good in [
            "staking_0_0",
            "filestorage_1_0",
            "my-contract2_80913826_3",
            "a_18446744073709551615_4294967295",
            // Kontor imposes no charset on the name and renders it as it is,
            // so these spellings are canonical too.
            "Foo.bar_1_2",
            "Staking_0_0",
            "1staking_1_0",
        ] {
            assert_eq!(
                parse_contract_address(&format!(" {good} "), "X").unwrap(),
                good
            );
        }
        for (bad, why) in [
            ("staking_00_0", "height"),
            ("staking_0_01", "tx index"),
            ("staking_+1_0", "height"),
            ("staking_1_x", "tx index"),
            ("staking_0", "3 parts"),
            ("staking_0_0_0", "3 parts"),
            ("_1_0", "name"),
            ("staking_18446744073709551616_0", "height"),
            ("staking_1_4294967296", "tx index"),
            ("staking_1_-1", "tx index"),
            ("stak ing_1_0", "name"),
        ] {
            let err = parse_contract_address(bad, "KONTOR_STAKING_CONTRACT_ADDRESS")
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("KONTOR_STAKING_CONTRACT_ADDRESS"),
                "{bad}: {err}"
            );
            assert!(err.contains(why), "{bad}: {err}");
        }

        let cli = Cli {
            kontor_staking_contract_address: "staking_00_0".to_string(),
            ..make_cli()
        };
        let err = Config::from_cli(&cli).unwrap_err().to_string();
        assert!(err.contains("KONTOR_STAKING_CONTRACT_ADDRESS"), "{err}");
        let cli = Cli {
            kontor_contract_address: "filestorage_0_01".to_string(),
            ..make_cli()
        };
        let err = Config::from_cli(&cli).unwrap_err().to_string();
        assert!(err.contains("KONTOR_CONTRACT_ADDRESS"), "{err}");
    }

    #[test]
    fn config_from_cli_trims_the_contract_address() {
        let cli = Cli {
            kontor_contract_address: "  filestorage_1_0  ".to_string(),
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();
        assert_eq!(config.kontor_contract_address, "filestorage_1_0");
    }

    /// No password means no admin UI, which is the default posture for a node
    /// nobody administers through a browser.
    #[test]
    fn config_from_cli_leaves_admin_password_empty_by_default() {
        let config = Config::from_cli(&make_cli()).unwrap();
        assert!(config.admin_password.is_empty());
    }

    #[test]
    fn config_from_cli_accepts_a_long_enough_admin_password() {
        let cli = Cli {
            admin_password: Some("correct horse battery".to_string()),
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();
        assert_eq!(config.admin_password.expose(), "correct horse battery");
    }

    /// A short password would be guessable through the login endpoint, so it is
    /// refused at startup rather than discovered after a wipe.
    #[test]
    fn config_from_cli_rejects_a_short_admin_password() {
        let cli = Cli {
            admin_password: Some("hunter2".to_string()),
            ..make_cli()
        };

        let err = Config::from_cli(&cli).unwrap_err();
        assert!(err.to_string().contains("ADMIN_PASSWORD"));
    }

    /// A variable left as `ADMIN_PASSWORD=` (or spaces) is an operator saying
    /// "no UI", not a one-character password to be rejected as too short.
    #[test]
    fn config_from_cli_treats_a_blank_admin_password_as_unset() {
        let cli = Cli {
            admin_password: Some("   ".to_string()),
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();
        assert!(config.admin_password.is_empty());
    }

    /// The whole point of the newtype: `{:?}` on the config must not print it.
    #[test]
    fn admin_password_is_redacted_in_debug_output() {
        let cli = Cli {
            admin_password: Some("correct horse battery".to_string()),
            ..make_cli()
        };

        let config = Config::from_cli(&cli).unwrap();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("correct horse battery"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert_eq!(format!("{:?}", AdminPassword::new(None)), "<empty>");
    }

    #[test]
    fn parse_storage_capacity_rejects_overflow() {
        let result = parse_storage_capacity("1 ZB", "STORAGE_CAPACITY");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds u64"));
    }

    #[test]
    fn config_from_cli_defaults_to_the_contract_stake_policy() {
        let config = Config::from_cli(&make_cli()).unwrap();
        assert_eq!(config.stake_policy, StakePolicy::default());
        assert_eq!(config.faucet_amount, Kor::whole(1000));
        assert_eq!(config.kontor_staking_contract_address, "staking_0_0");
    }

    #[test]
    fn config_from_cli_reads_stake_amounts_as_exact_decimals() {
        let cli = Cli {
            auto_stake: false,
            gas_reserve_kor: "2.5".to_string(),
            stake_target_kor: Some("250.000000000000000001".to_string()),
            faucet_amount_kor: "0.1".to_string(),
            claim_threshold_kor: "0.75".to_string(),
            unknown_collateral_estimate_kor: "2.5".to_string(),
            kontor_staking_contract_address: " staking_3_1 ".to_string(),
            ..make_cli()
        };
        let config = Config::from_cli(&cli).unwrap();
        assert!(!config.stake_policy.auto_stake);
        assert_eq!(config.stake_policy.gas_reserve.to_string(), "2.5");
        assert_eq!(
            config.stake_policy.stake_target.unwrap().to_string(),
            "250.000000000000000001"
        );
        assert_eq!(config.stake_policy.claim_threshold.to_string(), "0.75");
        assert_eq!(
            config.stake_policy.unknown_collateral_estimate.to_string(),
            "2.5"
        );
        assert_eq!(config.faucet_amount.to_string(), "0.1");
        assert_eq!(config.kontor_staking_contract_address, "staking_3_1");
    }

    /// Bad amounts are refused, and say which variable holds them. A reserve
    /// below one op's gas hold is one: Kontor takes the hold before running an
    /// `add-stake`, so staking everything above a zero reserve always fails.
    #[test]
    fn config_from_cli_rejects_bad_stake_amounts_by_name() {
        let minimum = Cli {
            gas_reserve_kor: "0.0001".to_string(),
            ..make_cli()
        };
        assert_eq!(
            Config::from_cli(&minimum).unwrap().stake_policy.gas_reserve,
            MIN_GAS_RESERVE
        );

        for (cli, name) in [
            (
                Cli {
                    gas_reserve_kor: "1e3".to_string(),
                    ..make_cli()
                },
                "KONTOR_STORAGE_GAS_RESERVE_KOR",
            ),
            (
                Cli {
                    gas_reserve_kor: "0".to_string(),
                    ..make_cli()
                },
                "KONTOR_STORAGE_GAS_RESERVE_KOR",
            ),
            (
                Cli {
                    gas_reserve_kor: "0.000099999999999999".to_string(),
                    ..make_cli()
                },
                "KONTOR_STORAGE_GAS_RESERVE_KOR",
            ),
            (
                Cli {
                    stake_target_kor: Some("0".to_string()),
                    ..make_cli()
                },
                "KONTOR_STORAGE_STAKE_TARGET_KOR",
            ),
            (
                Cli {
                    faucet_amount_kor: "-5".to_string(),
                    ..make_cli()
                },
                "KONTOR_STORAGE_FAUCET_AMOUNT_KOR",
            ),
            (
                Cli {
                    claim_threshold_kor: "0".to_string(),
                    ..make_cli()
                },
                "KONTOR_STORAGE_CLAIM_THRESHOLD_KOR",
            ),
            (
                Cli {
                    unknown_collateral_estimate_kor: "0".to_string(),
                    ..make_cli()
                },
                "KONTOR_STORAGE_UNKNOWN_COLLATERAL_ESTIMATE_KOR",
            ),
            (
                Cli {
                    kontor_staking_contract_address: " ".to_string(),
                    ..make_cli()
                },
                "KONTOR_STAKING_CONTRACT_ADDRESS",
            ),
        ] {
            let err = Config::from_cli(&cli).unwrap_err();
            assert!(err.to_string().contains(name), "{name}: {err}");
        }
    }

    /// `KONTOR_STORAGE_STAKE_TARGET_KOR=` left blank means "no target", not a
    /// parse error.
    #[test]
    fn config_from_cli_treats_a_blank_stake_target_as_unset() {
        let cli = Cli {
            stake_target_kor: Some("  ".to_string()),
            ..make_cli()
        };
        assert_eq!(
            Config::from_cli(&cli).unwrap().stake_policy.stake_target,
            None
        );
    }
}
