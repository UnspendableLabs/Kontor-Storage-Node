//! Shared HTTP client utilities.
//!
//! Centralizes HTTP client configuration and request execution
//! to avoid duplication across client modules.

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Default timeout for HTTP requests (30 seconds).
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for establishing connections (5 seconds).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a standard HTTP client with default timeouts.
///
/// Returns an error if the client cannot be built (e.g., TLS initialization fails).
pub fn build_http_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("failed to build HTTP client")
}

/// Check HTTP response status and return error with context if not successful.
///
/// On success, returns the response unchanged for further processing.
/// On failure, extracts the error body and returns a descriptive error.
pub async fn check_response_status(
    resp: reqwest::Response,
    context: &str,
) -> Result<reqwest::Response> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("{context} failed with status {status}: {body}"));
    }
    Ok(resp)
}

/// Execute a request and parse the JSON response.
///
/// On success, deserializes the response body as JSON into type `T`.
/// On failure, extracts the error body and returns a descriptive error.
#[allow(dead_code)]
pub async fn execute_request<T: DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T> {
    let resp = check_response_status(response, context).await?;
    resp.json::<T>()
        .await
        .with_context(|| format!("failed to deserialize {context}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_http_client_succeeds() {
        let client = build_http_client();
        assert!(client.is_ok(), "HTTP client should build successfully");
    }

    #[test]
    fn timeout_constants_are_reasonable() {
        assert_eq!(HTTP_TIMEOUT.as_secs(), 30);
        assert_eq!(CONNECT_TIMEOUT.as_secs(), 5);
    }

    #[tokio::test]
    async fn check_response_status_returns_ok_on_success() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        let client = build_http_client().unwrap();
        let resp = client.get(mock_server.uri()).send().await.unwrap();
        let result = check_response_status(resp, "test request").await;

        assert!(result.is_ok());
        let body = result.unwrap().text().await.unwrap();
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn check_response_status_returns_error_with_context_on_failure() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&mock_server)
            .await;

        let client = build_http_client().unwrap();
        let resp = client.get(mock_server.uri()).send().await.unwrap();
        let result = check_response_status(resp, "my operation").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("my operation failed with status 500"),
            "error should include context and status: {err}"
        );
        assert!(
            err.to_string().contains("internal error"),
            "error should include body: {err}"
        );
    }
}
