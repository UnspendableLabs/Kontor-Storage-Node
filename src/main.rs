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
use app::{run, Cli};
use clap::Parser;
use std::io;
use std::sync::Once;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    load_local_env()?;
    let cli = Cli::parse();
    let mut stdout = io::stdout();
    run(cli, &mut stdout).await
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
        let filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let _ = fmt()
            .with_env_filter(filter)
            .with_target(true)
            .compact()
            .try_init();
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
