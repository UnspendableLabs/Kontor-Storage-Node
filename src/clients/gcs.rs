use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::Deserialize;
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

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
}

impl GcsClient {
    /// Build a client from a service account JSON file path.
    pub async fn from_service_account_file(
        bucket: impl Into<String>,
        service_account_json: impl AsRef<Path>,
    ) -> Result<Self> {
        let contents = fs::read_to_string(service_account_json.as_ref())
            .with_context(|| "loading GCS service account json")?;
        let service_account: ServiceAccountKey =
            serde_json::from_str(&contents).context("parsing GCS service account json")?;

        let auth_url = service_account
            .token_uri
            .clone()
            .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string());

        Ok(Self {
            http: Client::new(),
            bucket: bucket.into(),
            service_account,
            auth_url,
            endpoint_url: "https://storage.googleapis.com".to_string(),
        })
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

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "uploading object {} failed with status {}: {}",
                object_name,
                status,
                body
            ));
        }

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

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "deleting object {} failed with status {}: {}",
                object_name,
                status,
                body
            ));
        }

        Ok(())
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

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "token exchange failed with status {status}: {body}"
            ));
        }

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

        let private_key_pem = self.service_account.private_key.replace("\\n", "\n");
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .context("parsing service account private key")?;

        encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
            .context("encoding JWT for GCS")
    }
}

#[derive(serde::Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}
