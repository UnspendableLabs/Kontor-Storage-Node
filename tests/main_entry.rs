use assert_cmd::cargo::cargo_bin_cmd;
use std::path::PathBuf;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn main_entry_runs_ping_with_cli_args() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&mock_server)
        .await;

    let temp_dir = TempDir::new().expect("create temp dir");
    let storage_dir = PathBuf::from(temp_dir.path()).join("storage");

    let mut cmd = cargo_bin_cmd!(env!("CARGO_PKG_NAME"));
    cmd.current_dir(temp_dir.path())
        .arg("--portal-url")
        .arg(mock_server.uri())
        .arg("--portal-api-key")
        .arg("secret")
        .arg("--database-url")
        .arg("sqlite::memory:")
        .arg("--storage-dir")
        .arg(&storage_dir)
        .arg("--server-address")
        .arg("127.0.0.1:0")
        .arg("ping");

    let output = cmd.output().expect("run binary");
    assert!(output.status.success(), "status: {}", output.status);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Portal URL:"),
        "expected cli info in stdout: {stdout}"
    );
    assert!(stdout.contains("pong"), "expected ping output: {stdout}");
}
