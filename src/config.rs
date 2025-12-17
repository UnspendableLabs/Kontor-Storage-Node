use crate::cli::Cli;

/// Application configuration derived from CLI arguments and environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub portal_url: String,
    pub database_url: String,
}

impl From<&Cli> for Config {
    fn from(cli: &Cli) -> Self {
        Self {
            portal_url: cli.portal_url.clone(),
            database_url: cli.database_url.clone(),
        }
    }
}
