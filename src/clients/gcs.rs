use super::http_helpers::{build_http_client, check_response_status, HTTP_TIMEOUT};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::thread_rng;
use reqwest::Client;
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use urlencoding::encode as url_encode;

/// Minimal Google Cloud Storage client for uploading agreement files using
/// service-account JWT flow and direct HTTP requests.
#[derive(Clone, Debug)]
pub struct GcsClient {
    http: Client,
    bucket: String,
    service_account: ServiceAccountKey,
    auth_url: String,
    endpoint_url: String,
}

#[derive(Clone, Deserialize, Debug)]
struct ServiceAccountKey {
    private_key: String,
    client_email: String,
    #[serde(default)]
    token_uri: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessTokenResponse {
    access_token: String,
}

/// Replaces `[n]` with `\n` so multi-line secrets can be stored in env vars (same convention as Horizon Portal).
fn unescape_json_string(input: &str) -> String {
    input.replace("[n]", "\\n")
}

impl GcsClient {
    /// Normalize PEM strings that may contain escaped newlines (e.g. `\n` in env vars)
    /// or Windows-style CRLF escapes. Returns a PEM string with real `\n` line breaks.
    fn normalize_private_key_pem(raw: &str) -> String {
        let unescaped = raw
            .replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\r", "\n");

        unescaped.lines().collect::<Vec<_>>().join("\n")
    }

    fn from_service_account_json_contents(
        bucket: impl Into<String>,
        contents: &str,
    ) -> Result<Self> {
        let service_account: ServiceAccountKey =
            serde_json::from_str(contents).context("parsing GCS service account json")?;

        let auth_url = service_account
            .token_uri
            .clone()
            .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string());

        let http = build_http_client().context("building GCS HTTP client")?;

        Ok(Self {
            http,
            bucket: bucket.into(),
            service_account,
            auth_url,
            endpoint_url: "https://storage.googleapis.com".to_string(),
        })
    }

    /// `raw` is either a filesystem path to service account JSON, or inline JSON (trimmed value
    /// starting with `{`). Inline JSON uses Portal-style `[n]` → `\n` unescaping for newlines.
    pub fn from_path_or_inline_json(bucket: impl Into<String>, raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let contents = if trimmed.starts_with('{') {
            unescape_json_string(trimmed)
        } else {
            fs::read_to_string(Path::new(trimmed))
                .with_context(|| format!("loading GCS service account json from {trimmed}"))?
        };
        Self::from_service_account_json_contents(bucket, &contents)
    }

    /// Test-only helper that allows overriding endpoints for mocking.
    #[cfg(test)]
    pub(crate) fn with_test_endpoints(
        bucket: impl Into<String>,
        client_email: impl Into<String>,
        private_key: impl Into<String>,
        auth_url: impl Into<String>,
        endpoint_url: impl Into<String>,
    ) -> Self {
        let auth_url = auth_url.into();
        let http = build_http_client().expect("building test GCS HTTP client");
        Self {
            http,
            bucket: bucket.into(),
            service_account: ServiceAccountKey {
                private_key: private_key.into(),
                client_email: client_email.into(),
                token_uri: Some(auth_url.clone()),
            },
            auth_url,
            endpoint_url: endpoint_url.into(),
        }
    }

    /// Upload raw bytes as an object named `object_name` into the configured bucket.
    pub async fn upload_bytes(&self, object_name: &str, bytes: &[u8]) -> Result<()> {
        let token = self.fetch_access_token().await?;
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.endpoint_url,
            self.bucket,
            url_encode(object_name)
        );

        let resp = self
            .http
            .post(url)
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .context("sending upload request to GCS")?;

        check_response_status(resp, &format!("upload object {object_name}")).await?;
        Ok(())
    }

    /// Best-effort deletion of an object previously uploaded.
    pub async fn delete_object(&self, object_name: &str) -> Result<()> {
        let token = self.fetch_access_token().await?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.endpoint_url,
            self.bucket,
            url_encode(object_name)
        );

        let resp = self
            .http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await
            .context("sending delete request to GCS")?;

        check_response_status(resp, &format!("delete object {object_name}")).await?;
        Ok(())
    }

    /// Download an object from GCS and return its bytes.
    pub async fn download_to_bytes(&self, object_name: &str) -> Result<Bytes> {
        let token = self.fetch_access_token().await?;
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            self.endpoint_url,
            self.bucket,
            url_encode(object_name)
        );

        let resp = self
            .http
            .get(url)
            .bearer_auth(token)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await
            .context("downloading object from GCS")?;

        let resp = check_response_status(resp, &format!("download object {object_name}")).await?;
        resp.bytes()
            .await
            .context("reading object body from GCS response")
    }

    /// Create a V4 signed download URL, matching the Horizon-Portal behavior (direct redirect to GCS).
    pub fn create_signed_download_url(
        &self,
        object_name: &str,
        force_download: bool,
        filename: Option<&str>,
    ) -> Result<String> {
        let private_key = self.parse_private_key()?;
        let (x_goog_date, short_date) = Self::timestamp_strings();
        let expiration_seconds: i64 = 900; // 15 minutes, short-lived

        let canonical_uri = self.canonical_uri(object_name);
        let host = self.extract_host()?;
        let (canonical_headers, signed_headers) = Self::canonical_headers(&host);

        let scope = format!("{short_date}/auto/storage/goog4_request");
        let credential = format!("{}/{}", self.service_account.client_email, scope);

        let mut query_params = vec![
            (
                "X-Goog-Algorithm".to_string(),
                "GOOG4-RSA-SHA256".to_string(),
            ),
            (
                "X-Goog-Credential".to_string(),
                url_encode(&credential).to_string(),
            ),
            ("X-Goog-Date".to_string(), x_goog_date.clone()),
            ("X-Goog-Expires".to_string(), expiration_seconds.to_string()),
            ("X-Goog-SignedHeaders".to_string(), signed_headers.clone()),
        ];

        if force_download {
            let disposition = Self::content_disposition(filename);
            query_params.push((
                "response-content-disposition".to_string(),
                url_encode(&disposition).to_string(),
            ));
        }

        query_params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let canonical_query = Self::canonical_query(&query_params);

        let canonical_request = format!(
            "GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
        );

        let string_to_sign = {
            let request_hash_hex = Self::sha256_hex(canonical_request.as_bytes());
            format!("GOOG4-RSA-SHA256\n{x_goog_date}\n{scope}\n{request_hash_hex}")
        };

        let signature_hex = self.sign_string(&private_key, string_to_sign.as_bytes())?;

        Ok(format!(
            "{}{}{}{}&X-Goog-Signature={}",
            self.endpoint_url.trim_end_matches('/'),
            canonical_uri,
            "?",
            canonical_query,
            signature_hex
        ))
    }

    fn parse_private_key(&self) -> Result<RsaPrivateKey> {
        let pem = Self::normalize_private_key_pem(&self.service_account.private_key);
        RsaPrivateKey::from_pkcs8_pem(&pem)
            .map_err(|err| anyhow!("failed to parse service account private key: {err}"))
    }

    fn sign_string(&self, key: &RsaPrivateKey, message: &[u8]) -> Result<String> {
        let mut rng = thread_rng();
        // rsa::Pkcs1v15Sign expects the input to already be hashed.
        let digest = Sha256::digest(message);
        let signature = key
            .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<Sha256>(), &digest)
            .context("signing string for GCS URL")?;
        Ok(hex::encode(signature))
    }

    fn timestamp_strings() -> (String, String) {
        use chrono::Utc;
        let now = Utc::now();
        let x_goog_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let short_date = now.format("%Y%m%d").to_string();
        (x_goog_date, short_date)
    }

    fn canonical_uri(&self, object_name: &str) -> String {
        // Encode the entire object name, including slashes, to ensure the path is fully encoded.
        let encoded_object = url_encode(object_name);
        format!("/{}/{}", self.bucket, encoded_object)
    }

    fn extract_host(&self) -> Result<String> {
        let url = reqwest::Url::parse(&self.endpoint_url)
            .map_err(|err| anyhow!("invalid endpoint_url {}: {err}", self.endpoint_url))?;
        url.host_str()
            .map(std::string::ToString::to_string)
            .ok_or_else(|| anyhow!("endpoint_url has no host: {}", self.endpoint_url))
    }

    fn canonical_headers(host: &str) -> (String, String) {
        let canonical_headers = format!("host:{host}\n");
        let signed_headers = "host".to_string();
        (canonical_headers, signed_headers)
    }

    fn canonical_query(query_params: &[(String, String)]) -> String {
        query_params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn content_disposition(filename: Option<&str>) -> String {
        filename.map_or_else(
            || "attachment".to_string(),
            |fname| format!("attachment; filename=\"{}\"", fname.replace('"', "\\\"")),
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    async fn fetch_access_token(&self) -> Result<String> {
        let jwt = self.create_jwt()?;
        let resp = self
            .http
            .post(&self.auth_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .context("exchanging JWT for access token")?;

        let resp = check_response_status(resp, "token exchange").await?;
        let token: AccessTokenResponse =
            resp.json().await.context("parsing access token response")?;
        Ok(token.access_token)
    }

    fn create_jwt(&self) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before UNIX_EPOCH")?
            .as_secs() as i64;
        let claims = JwtClaims {
            iss: self.service_account.client_email.clone(),
            scope: "https://www.googleapis.com/auth/devstorage.read_write".to_string(),
            aud: self.auth_url.clone(),
            exp: now + 3600,
            iat: now,
        };

        let private_key_pem = Self::normalize_private_key_pem(&self.service_account.private_key);
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .context("parsing service account private key")?;

        encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
            .context("encoding JWT for GCS")
    }
}

#[derive(Serialize, Deserialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[cfg(test)]
mod tests {
    use super::{
        unescape_json_string, AccessTokenResponse, GcsClient, JwtClaims, ServiceAccountKey,
    };
    use bytes::Bytes;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use reqwest::Client;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_bytes, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnumunEUnoZIs5\nDhEXTNTyJPFxsZMxgRhLs7m6aiVu7GrDgoWFMoLy/B6Ccl2c9ml/RzuK5uKbJKM9\ntcwA90gpp536aLWB0BbQuWtfceU3BmQWFtQRXqCww/o462cujXhcMe5bVPvE9b/5\nyV+oWmKa42tw4x5//Cj8LGAw8aQwlC+OQ19iA+vmKx7xjs0uBFtQHnjGxekT71vp\nLgv53SVi5yUscz9Scy/VuBkNfOCaEz5zV+EUplYuvRMVEJ0Pvk1wOYjby4Gz+OVI\nrp1+1RFBEeTu2zo06E4o23pfz5DbZaBMZ8qK3WkNx6eQOuYK6Zrq+zM5/Uoq6fqQ\nAIuYpCNxAgMBAAECggEAB1pTx9IpNEfcFpc4RpY2q5rU/s/zDPOE1iS92p82nuM8\nVu/M3Kb3OKG20K8kzXG79DlyMcenXXfAtD7Y/53XiwPvGAApHNS7e1D1lQyQKNZd\n4t4DU/ObBcTBnmcrcc3/3cLOmTBjjSHc1Z1vVRkJQ5L+rcc3GhM61Ls5SEv/j6WN\nFw/fnYGtxUUXBz1gVvok0o89qTgW0Pt7SWrUkbAhrsGeTFpzNbicgRsBUXJJdRcl\nvK5rwKSPUhiIVhpQ78usSLdO30X3Bfvf/GQpR56/UgDqkn20ZMpJhKrAxSbmLSu9\nhgkIbLAlABxdYUbGFp5aTALAJ8EyZn8MU9RRuL9DcQKBgQDp263xaTlx8BgbKnq1\nwY+SxuDlGz/LoGYjF6v6FNHM1hQ5v2FpxaxF5EDUm3fdh+Z9yegL/g8GQdQQnelG\nA43VACvGAESw1ilsBDl6TZ+LZY4MTQrWSGUqQxt3APu3lHDAXkipHu2X3cv/3VrO\nDGs2WYWPiMxg1ZkIBojyZQ0SnQKBgQC3m910nvJIJ+WLXeXiG2qN147/5GU7Yma2\n0pEhQ4XVN/f7joGzUXLeB0BXNNbdKuRqEQ1r2VkH3qqY6HAL6/fK01qEhWBLv1hu\ndkEhEruK9WxzA/vLgmqFBsi04IFlnK70RCXckWZEHFjnnoutqAWpl7FTRiTeT8Bv\nHgmX2+lh5QKBgDAuADIiWaFts6m1IL7dd/TnYGITMRuEmkZUlCvbqjWnTVdwZGNk\nRE/J7Mlglltfqk70EAiYeQPy//vEbNDt3oSpmlsapww/sxz76dOWtm4DqDZEkR0A\noUcJuFjWLQXvYSNgyVt+cbi+C09VjWWyDUyPOQMPTfwNRY/vuLsnsn/JAoGBAKrW\n0Ri46DBxRukFJmfbIKr3/etlZTf7GB1WEYnE3RsGZ6vd7hqeV2X1k01RMfc5+Kwk\nT7ug0XE8IroB1HeTSM2lGJ0jyPTSBoNJbtJKLsxeDVl7RGcYYuqB5HBAUMXuIu/P\nFPeFJoWLZsGkyMx9AT/KkEkuhBGCXUhGx6BQE3htAoGAbEGbhHV8oU7NYKEmVyWM\nwfEQXGH2QQpHsj7xkTywOKEneaMkVUzA5GwF7CQEvk/2xXEgze+haaRGxFQJTO5m\nGK2ECeQhTwXvNi+3/MEMCdoPYuckF4hCVzsGwfkVBPf1zcOw0k0+EEsqbWwtXi2l\njIyC7b2m2fgAI0Ltt1btCfo=\n-----END PRIVATE KEY-----";
    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp7prpxFJ6GSLOQ4RF0zU\n8iTxcbGTMYEYS7O5umolbuxqw4KFhTKC8vwegnJdnPZpf0c7iubimySjPbXMAPdI\nKaed+mi1gdAW0LlrX3HlNwZkFhbUEV6gsMP6OOtnLo14XDHuW1T7xPW/+clfqFpi\nmuNrcOMef/wo/CxgMPGkMJQvjkNfYgPr5ise8Y7NLgRbUB54xsXpE+9b6S4L+d0l\nYuclLHM/UnMv1bgZDXzgmhM+c1fhFKZWLr0TFRCdD75NcDmI28uBs/jlSK6dftUR\nQRHk7ts6NOhOKNt6X8+Q22WgTGfKit1pDcenkDrmCuma6vszOf1KKun6kACLmKQj\ncQIDAQAB\n-----END PUBLIC KEY-----";

    fn temp_path(name: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("gcs_client")
            .join(format!("{name}_{id}"))
    }

    fn service_account_key_with_newlines(escaped: bool) -> String {
        if escaped {
            TEST_PRIVATE_KEY.replace('\n', "\\n")
        } else {
            TEST_PRIVATE_KEY.to_string()
        }
    }

    fn write_service_account_file(token_uri: Option<&str>, escaped_key: bool) -> PathBuf {
        let path = temp_path("service_account.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let key = service_account_key_with_newlines(escaped_key);
        let json = json!({
            "private_key": key,
            "client_email": "svc@example.com",
            "token_uri": token_uri
        });
        fs::write(&path, json.to_string()).unwrap();
        path
    }

    fn client_with_endpoints(auth_url: String, endpoint_url: String) -> GcsClient {
        let service_account = ServiceAccountKey {
            private_key: service_account_key_with_newlines(false),
            client_email: "svc@example.com".to_string(),
            token_uri: Some(auth_url.clone()),
        };

        GcsClient {
            http: Client::new(),
            bucket: "test-bucket".to_string(),
            service_account,
            auth_url,
            endpoint_url,
        }
    }

    #[test]
    fn unescape_json_string_replaces_portal_newline_markers() {
        assert_eq!(unescape_json_string("hello[n]world"), "hello\\nworld");
        assert_eq!(unescape_json_string("no escapes"), "no escapes");
        assert_eq!(unescape_json_string("[n][n]"), "\\n\\n");
    }

    #[test]
    fn from_path_or_inline_json_reads_file_path() {
        let path = write_service_account_file(Some("https://auth.example/token"), true);
        let client = GcsClient::from_path_or_inline_json("bucket-1", &path.to_string_lossy())
            .expect("should parse service account");

        assert_eq!(client.bucket, "bucket-1");
        assert_eq!(client.auth_url, "https://auth.example/token");
    }

    #[test]
    fn from_path_or_inline_json_uses_default_auth_url_when_missing_in_file() {
        let path = write_service_account_file(None, true);
        let client = GcsClient::from_path_or_inline_json("bucket-2", &path.to_string_lossy())
            .expect("should parse service account");

        assert_eq!(client.bucket, "bucket-2");
        assert_eq!(client.auth_url, "https://oauth2.googleapis.com/token");
    }

    #[test]
    fn from_path_or_inline_json_accepts_inline_json_with_n_escapes() {
        let pem_line1 = "-----BEGIN PRIVATE KEY-----";
        let pem_line2 = "LINE2";
        let json = format!(
            r#"{{"private_key":"{pem_line1}[n]{pem_line2}","client_email":"svc@example.com","token_uri":"https://oauth2.googleapis.com/token"}}"#
        );
        let client = GcsClient::from_path_or_inline_json("bucket-inline", &json)
            .expect("inline json should parse");
        assert_eq!(client.bucket, "bucket-inline");
        assert!(client.service_account.private_key.contains('\n'));
        assert!(client.service_account.private_key.contains(pem_line1));
    }

    #[tokio::test]
    async fn upload_bytes_sends_body_and_bearer_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                    access_token: "token-123".to_string(),
                }),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/test-bucket/o"))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", "file.txt"))
            .and(header("authorization", "Bearer token-123"))
            .and(header("content-type", "application/octet-stream"))
            .and(body_bytes("hello"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        client
            .upload_bytes("file.txt", b"hello")
            .await
            .expect("upload should succeed");
    }

    #[tokio::test]
    async fn upload_bytes_returns_error_on_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "bad-token"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/test-bucket/o"))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", "fail.bin"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        let err = client
            .upload_bytes("fail.bin", b"bytes")
            .await
            .expect_err("upload should fail");

        assert!(err.to_string().contains("status 500"));
        assert!(err.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn delete_object_returns_ok_on_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "del-token"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("DELETE"))
            .and(path("/storage/v1/b/test-bucket/o/object.txt"))
            .and(header("authorization", "Bearer del-token"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        client
            .delete_object("object.txt")
            .await
            .expect("delete should succeed");
    }

    #[tokio::test]
    async fn delete_object_returns_error_on_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "del-bad"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("DELETE"))
            .and(path("/storage/v1/b/test-bucket/o/will-fail"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        let err = client
            .delete_object("will-fail")
            .await
            .expect_err("delete should fail");

        assert!(err.to_string().contains("status 404"));
        assert!(err.to_string().contains("missing"));
    }

    #[tokio::test]
    async fn download_to_bytes_fetches_object() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                    access_token: "get-token".to_string(),
                }),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/storage/v1/b/test-bucket/o/object.txt"))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer get-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello gcs"))
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        let bytes = client
            .download_to_bytes("object.txt")
            .await
            .expect("download should succeed");

        assert_eq!(bytes, Bytes::from_static(b"hello gcs"));
    }

    #[tokio::test]
    async fn download_to_bytes_surfaces_http_errors() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                    access_token: "byte-token".to_string(),
                }),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/storage/v1/b/test-bucket/o/fail-bytes.bin"))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer byte-token"))
            .respond_with(ResponseTemplate::new(503).set_body_string("nope"))
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        let err = client
            .download_to_bytes("fail-bytes.bin")
            .await
            .expect_err("non-success should error");

        let msg = err.to_string();
        assert!(
            msg.contains("download object") && msg.contains("failed with status 503"),
            "unexpected message: {msg}"
        );
        assert!(msg.contains("nope"), "expected body text: {msg}");
    }

    #[tokio::test]
    async fn create_signed_download_url_includes_required_params() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                    access_token: "redirect-token".to_string(),
                }),
            )
            .mount(&mock_server)
            .await;

        let client =
            client_with_endpoints(format!("{}/token", mock_server.uri()), mock_server.uri());

        let url = client
            .create_signed_download_url("folder/file name.pdf", true, Some("file name.pdf"))
            .expect("signed url should be generated");

        assert!(
            url.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"),
            "algorithm should be present: {url}"
        );
        assert!(
            url.contains("X-Goog-SignedHeaders=host"),
            "signed headers should be present: {url}"
        );
        assert!(
            url.contains(
                "response-content-disposition=attachment%3B%20filename%3D%22file%20name.pdf%22"
            ),
            "content disposition should be preserved: {url}"
        );
        assert!(
            url.contains("/test-bucket/folder%2Ffile%20name.pdf"),
            "object path should be encoded: {url}"
        );
        assert!(
            url.contains("X-Goog-Signature="),
            "signature must be included: {url}"
        );
    }

    #[test]
    fn content_disposition_encodes_filenames() {
        let with_name = GcsClient::content_disposition(Some("a \"weird\" name.txt"));
        assert_eq!(
            with_name, "attachment; filename=\"a \\\"weird\\\" name.txt\"",
            "quotes should be escaped"
        );

        let defaulted = GcsClient::content_disposition(None);
        assert_eq!(defaulted, "attachment");
    }

    #[tokio::test]
    async fn fetch_access_token_propagates_http_errors() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&mock_server)
            .await;

        let client = client_with_endpoints(
            format!("{}/token", mock_server.uri()),
            "https://storage.example".to_string(),
        );

        let err = client
            .fetch_access_token()
            .await
            .expect_err("token exchange should fail");

        assert!(err.to_string().contains("token exchange failed"));
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn create_jwt_replaces_escaped_newlines() {
        let service_account = ServiceAccountKey {
            private_key: service_account_key_with_newlines(true),
            client_email: "svc@example.com".to_string(),
            token_uri: Some("https://auth.example".to_string()),
        };

        let client = GcsClient {
            http: Client::new(),
            bucket: "test-bucket".to_string(),
            service_account,
            auth_url: "https://auth.example".to_string(),
            endpoint_url: "https://storage.example".to_string(),
        };

        let jwt = client.create_jwt().expect("jwt creation should succeed");

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;

        let decoded = decode::<JwtClaims>(
            &jwt,
            &DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap(),
            &validation,
        )
        .expect("jwt should decode");

        assert_eq!(decoded.claims.iss, "svc@example.com");
        assert_eq!(decoded.claims.aud, "https://auth.example");
        assert!(decoded.claims.exp > decoded.claims.iat);
    }

    #[test]
    fn create_jwt_errors_on_invalid_key() {
        let service_account = ServiceAccountKey {
            private_key: "not-a-key".to_string(),
            client_email: "svc@example.com".to_string(),
            token_uri: None,
        };

        let client = GcsClient {
            http: Client::new(),
            bucket: "bucket".to_string(),
            service_account,
            auth_url: "https://auth.example".to_string(),
            endpoint_url: "https://storage.example".to_string(),
        };

        let err = client.create_jwt().expect_err("should fail parsing key");
        assert!(err
            .to_string()
            .contains("parsing service account private key"));
    }
}
