//! Node registration verification with Horizon Market.

use crate::clients::{NodeCheckResult, NodeInfo, PortalClient};
use crate::node::onboarding::verification::verify_bls_key_match;
use anyhow::{anyhow, Result};

/// Check if the node exists in Horizon Market.
pub async fn check_node_exists(client: &PortalClient, node_id: &str) -> Result<NodeInfo> {
    match client.check_node(node_id).await? {
        NodeCheckResult::Found(info) => Ok(info),
        NodeCheckResult::NotFound => Err(anyhow!(
            "Node {} not found in Horizon Market.\n\n\
                Please register as a Storage Node at:\n\
                https://horizon.market\n\n\
                After completing registration, you will receive a Node ID that you can use\n\
                to configure this application.",
            node_id
        )),
    }
}

/// Verify that the BLS key has been registered on Horizon Market.
pub async fn verify_bls_registration(
    client: &PortalClient,
    node_id: &str,
    expected_key: &str,
) -> Result<NodeInfo> {
    match client.check_node(node_id).await? {
        NodeCheckResult::Found(info) => {
            let remote_key = info
                .bls_public_key
                .as_ref()
                .filter(|k| !k.is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "BLS key not found on Horizon Market.\n\n\
                        Please make sure you have registered your BLS public key at:\n\
                        https://horizon.market/profile?show=node-storage\n\n\
                        Then restart the application to try again."
                    )
                })?;
            verify_bls_key_match(expected_key, remote_key)?;
            Ok(info)
        }
        NodeCheckResult::NotFound => {
            Err(anyhow!("Node {} was removed from Horizon Market", node_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlsKeyPair;
    use serde_json::json;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn check_node_exists_returns_info_when_found() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-exists/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-exists",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": "pubkey123"
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir);
        let info = check_node_exists(&client, "NODE-exists").await.unwrap();

        assert_eq!(info.bls_public_key, Some("pubkey123".to_string()));
    }

    #[tokio::test]
    async fn check_node_exists_fails_when_not_found() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-missing/check"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {
                    "code": "NODE_NOT_FOUND",
                    "message": "node not found",
                    "status": 404
                }
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir);
        let err = check_node_exists(&client, "NODE-missing")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not found in Horizon Market"));
    }

    #[tokio::test]
    async fn verify_bls_registration_succeeds_with_matching_key() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");

        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-verify/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-verify",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir);
        let info = verify_bls_registration(&client, "NODE-verify", &public_key)
            .await
            .unwrap();

        assert_eq!(info.bls_public_key, Some(public_key));
    }

    #[tokio::test]
    async fn verify_bls_registration_fails_when_no_key_registered() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-nokey/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-nokey",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": null
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir);
        let err = verify_bls_registration(&client, "NODE-nokey", "somepubkey")
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("BLS key not found on Horizon Market"));
    }

    #[tokio::test]
    async fn verify_bls_registration_fails_when_node_removed() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-removed/check"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {
                    "code": "NODE_NOT_FOUND",
                    "message": "node not found",
                    "status": 404
                }
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir);
        let err = verify_bls_registration(&client, "NODE-removed", "somepubkey")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("was removed from Horizon Market"));
    }

    #[tokio::test]
    async fn verify_bls_registration_fails_when_key_mismatch() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-mismatch/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-mismatch",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": "differentkey"
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir);
        let err = verify_bls_registration(&client, "NODE-mismatch", "mypubkey")
            .await
            .unwrap_err();

        assert!(err.to_string().contains("BLS public key mismatch"));
    }
}
