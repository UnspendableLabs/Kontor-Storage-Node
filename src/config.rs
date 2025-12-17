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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};

    #[test]
    fn config_from_cli_clones_fields() {
        let mut cli = Cli {
            portal_url: "https://portal.example/api".to_string(),
            database_url: "sqlite://localhost/mydb".to_string(),
            command: Commands::Ping,
        };

        let config = Config::from(&cli);

        cli.portal_url.push_str("/extra");
        cli.database_url.push_str("?mode=ro");

        assert_eq!(config.portal_url, "https://portal.example/api");
        assert_eq!(config.database_url, "sqlite://localhost/mydb");
    }
}
