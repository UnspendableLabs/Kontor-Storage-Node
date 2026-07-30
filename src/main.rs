mod app;
mod clients;
mod crypto;
mod database;
mod entities;
mod node;
mod server;

#[cfg(test)]
pub mod testutils;

use anyhow::{anyhow, Context, Result};
use app::{cli::migrate_legacy_env_vars, run, Cli, Outcome, SharedWriter, RESTART_EXIT_CODE};
use clap::Parser;
use std::io::{self, Write};
use std::sync::Once;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    load_local_env()?;
    migrate_legacy_env_vars();
    let cli = Cli::parse();
    let mut writer = SharedWriter::stdout();

    match run(cli, writer.clone()).await? {
        Outcome::Shutdown => Ok(()),
        // Returning would exit `0`, which the on-failure restart policies that
        // Railway and Docker Compose default to read as "stay down". Exiting
        // explicitly is also why stdout is flushed by hand here: the process
        // ends without unwinding, so nothing else will.
        //
        // Excluded from coverage: a test that reached this line would end the
        // test process. What leads here is covered — see the run loop's
        // `Outcome::Restart` tests in `app::runtime`.
        // LCOV_EXCL_START
        Outcome::Restart => {
            let _ = writer.flush();
            std::process::exit(RESTART_EXIT_CODE)
        } // LCOV_EXCL_STOP
    }
}

pub fn load_local_env() -> Result<()> {
    match std::fs::metadata(".env.local") {
        Ok(meta) => {
            if meta.is_dir() {
                return Err(anyhow!("failed to load .env.local: path is a directory"));
            }

            let contents =
                std::fs::read_to_string(".env.local").context("failed to read .env.local")?;
            dotenvy::from_read(contents.as_bytes()).context("failed to load .env.local")?;
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).context("failed to stat .env.local"),
    }
}

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        if let Err(e) = fmt()
            .with_env_filter(filter)
            .with_target(true)
            .compact()
            .try_init()
        {
            eprintln!("warning: failed to initialize tracing subscriber: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_logging_runs_once() {
        init_logging();
        init_logging();
    }
}
