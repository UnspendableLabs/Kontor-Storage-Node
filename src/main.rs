use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;

#[derive(Parser, Debug)]
#[command(author, version, about = "Kontor Storage Node CLI")]
struct Cli {
    /// Portal API base URL (e.g. https://portal.example.com/api)
    #[arg(long, env = "PORTAL_API_URL", default_value = "http://localhost:8080")]
    portal_url: String,

    /// Command to run
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check connectivity with the Portal API
    Ping,
}

struct PortalClient {
    base_url: String,
    http: Client,
}

impl PortalClient {
    fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into();
        Self {
            base_url,
            http: Client::new(),
        }
    }

    async fn ping(&self) -> Result<String> {
        let url = format!("{}/health", self.base_url.trim_end_matches('/'));
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let body = resp.text().await?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(anyhow!("Portal ping failed with status {status}: {body}"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = PortalClient::new(cli.portal_url);

    match cli.command {
        Commands::Ping => {
            let body = client.ping().await?;
            println!("{body}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn portal_client_new_stores_base_url() {
        let client = PortalClient::new("https://example.com/api");
        assert_eq!(client.base_url, "https://example.com/api");
    }

    #[test]
    fn portal_client_new_trims_trailing_slash_in_ping() {
        let client = PortalClient::new("https://example.com/api/");
        // The trailing slash trimming happens in ping(), not in new()
        assert_eq!(client.base_url, "https://example.com/api/");
    }

    #[tokio::test]
    async fn ping_success_returns_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri());
        let result = client.ping().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "OK");
    }

    #[tokio::test]
    async fn ping_success_with_trailing_slash() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("healthy"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(format!("{}/", mock_server.uri()));
        let result = client.ping().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "healthy");
    }

    #[tokio::test]
    async fn ping_failure_returns_error_with_status_and_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri());
        let result = client.ping().await;

        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("500"));
        assert!(error_message.contains("Internal Server Error"));
    }

    #[tokio::test]
    async fn ping_failure_on_404() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri());
        let result = client.ping().await;

        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("404"));
    }
}
