//! Shared HTTP client utilities.
//!
//! Centralizes HTTP client configuration and request execution
//! to avoid duplication across client modules.

use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;

/// Typed error returned by `check_response_status` when an HTTP response is
/// non-success.
///
/// This wraps the status code so callers can match on it (e.g. to detect 404)
/// without resorting to fragile substring matching on the error's `Display` text.
/// `Display` intentionally produces the same `"{context} failed with status {status}: {body}"`
/// text the helper used to emit via `anyhow!`, so existing callers and tests
/// that inspect the error message continue to work unchanged.
#[derive(Debug)]
pub struct HttpStatusError {
    pub status: reqwest::StatusCode,
    pub body: String,
    pub context: String,
}

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} failed with status {}: {}",
            self.context, self.status, self.body
        )
    }
}

impl std::error::Error for HttpStatusError {}

impl HttpStatusError {
    /// The structured `code` of a Portal error envelope,
    /// `{"error": {"code": "...", "message": "...", "status": 422}}`.
    ///
    /// `None` when the body is not that envelope — a proxy's HTML page, an
    /// older flat `{"code": ...}` body is accepted too since the faucet answers
    /// in that shape.
    #[must_use]
    pub fn api_code(&self) -> Option<String> {
        let body: serde_json::Value = serde_json::from_str(&self.body).ok()?;
        body.get("error")
            .and_then(|error| error.get("code"))
            .or_else(|| body.get("code"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    }

    /// The human-readable `message` of the same envelope.
    #[must_use]
    pub fn api_message(&self) -> Option<String> {
        let body: serde_json::Value = serde_json::from_str(&self.body).ok()?;
        body.get("error")
            .and_then(|error| error.get("message"))
            .or_else(|| body.get("message"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    }
}

/// The status and Portal error code of a failed request, if `error` is one.
#[must_use]
pub fn status_and_code(error: &anyhow::Error) -> Option<(u16, Option<String>)> {
    error
        .downcast_ref::<HttpStatusError>()
        .map(|status| (status.status.as_u16(), status.api_code()))
}

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
/// On failure, extracts the error body and returns an [`HttpStatusError`] wrapped in
/// `anyhow::Error`. Callers that need to react to a specific status (e.g. 404)
/// can `downcast_ref::<HttpStatusError>()` instead of substring-matching the
/// error message. The `Display` text is preserved verbatim for backwards compatibility.
pub async fn check_response_status(
    resp: reqwest::Response,
    context: &str,
) -> Result<reqwest::Response> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::Error::new(HttpStatusError {
            status,
            body,
            context: context.to_string(),
        }));
    }
    Ok(resp)
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

    #[tokio::test]
    async fn check_response_status_error_is_downcastable_to_http_status_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
            .mount(&mock_server)
            .await;

        let client = build_http_client().unwrap();
        let resp = client.get(mock_server.uri()).send().await.unwrap();
        let err = check_response_status(resp, "lookup")
            .await
            .expect_err("non-success should be an error");

        let typed = err
            .downcast_ref::<HttpStatusError>()
            .expect("error should be downcastable to HttpStatusError");
        assert_eq!(typed.status, reqwest::StatusCode::NOT_FOUND);
        assert_eq!(typed.context, "lookup");
        assert_eq!(typed.body, "missing");
        assert!(
            err.to_string().contains("lookup failed with status 404"),
            "Display text should be preserved verbatim: {err}"
        );
    }

    fn status_error(body: &str) -> HttpStatusError {
        HttpStatusError {
            status: reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            body: body.to_string(),
            context: "join".to_string(),
        }
    }

    /// The Portal's envelope nests the code; the faucet's older errors do not.
    /// Both are read, and anything else is simply "no code".
    #[test]
    fn api_code_reads_the_portal_envelope_and_the_flat_shape() {
        let nested = status_error(
            r#"{"error":{"code":"INSUFFICIENT_COLLATERAL","message":"needs 30","status":422}}"#,
        );
        assert_eq!(
            nested.api_code().as_deref(),
            Some("INSUFFICIENT_COLLATERAL")
        );
        assert_eq!(nested.api_message().as_deref(), Some("needs 30"));

        let flat = status_error(r#"{"code":"FAUCET_UNAVAILABLE","message":"off"}"#);
        assert_eq!(flat.api_code().as_deref(), Some("FAUCET_UNAVAILABLE"));

        assert_eq!(status_error("<html>bad gateway</html>").api_code(), None);
        assert_eq!(status_error(r#"{"error":"plain"}"#).api_code(), None);

        let wrapped = anyhow::Error::new(nested);
        assert_eq!(
            status_and_code(&wrapped),
            Some((422, Some("INSUFFICIENT_COLLATERAL".to_string())))
        );
        assert_eq!(status_and_code(&anyhow::anyhow!("offline")), None);
    }
}
