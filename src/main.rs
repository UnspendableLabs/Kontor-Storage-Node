mod cli;
mod clients;
mod config;
mod database;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};
use clients::PortalClient;
use config::Config;
use database::DBClient;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::from(&cli);

    println!("Portal URL: {}", config.portal_url);
    println!("Database URL: {}", config.database_url);

    let db = DBClient::new(&config.database_url).await?;
    let _conn = db.connection();
    let client = PortalClient::new(&config.portal_url);

    match cli.command {
        Commands::Ping => {
            let body = client.ping().await?;
            println!("{body}");
        }
    }

    Ok(())
}
