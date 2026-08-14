//! The dashboard's static files, compiled into the binary.
//!
//! They used to be served with `ServeDir::new("static")`, which resolves
//! against the *working directory*. That holds for the Docker image, which
//! sets `WORKDIR /app` and copied `static/` in beside the binary, and for
//! `cargo run` from a checkout. It does not hold for `cargo install
//! kontor-storage-node`: the published tarball carries `static/`, but what
//! lands in `~/.cargo/bin` is a lone executable, and whatever directory the
//! operator happens to be in when they start the node is not it. Every asset
//! answered 404 and the dashboard rendered unstyled.
//!
//! Embedding is what the rest of the server already does — the dashboard shell
//! and the whole `/admin` page are `include_str!`'d — so this only extends the
//! same rule to the three files that were still on disk. The node ships as one
//! file, and there is no deployment where the page is half-served.
//!
//! [`serve`] answers with a strong `ETag` (the content hash) and honours
//! `If-None-Match`, so a reload costs a 304 rather than the body. The hash
//! changes when the file does, which is what makes it safe to cache a URL that
//! never changes name.

use axum::body::Body;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use http::{header, HeaderValue, StatusCode};
use rust_embed::Embed;

/// Everything under `static/`, embedded at compile time.
#[derive(Embed)]
#[folder = "static/"]
pub struct Assets;

/// Fetch an embedded asset by its path under `static/`.
///
/// Returns `None` for anything not embedded, which is every path an attacker
/// could ask for: there is no filesystem behind this, so `../` traversal has
/// nothing to reach.
pub fn get(path: &str) -> Option<rust_embed::EmbeddedFile> {
    Assets::get(path)
}

/// `GET /static/*path` — serve one embedded asset.
pub async fn serve(Path(path): Path<String>, headers: http::HeaderMap) -> Response {
    let Some(asset) = get(path.as_str()) else {
        return (StatusCode::NOT_FOUND, "asset not found").into_response();
    };

    // rust-embed hands back the hash as bytes; a strong ETag is that hash
    // rendered as the quoted hex string the header grammar wants.
    let etag = format!("\"{}\"", hex::encode(asset.metadata.sha256_hash()));

    // `If-None-Match` may carry a list; a match on any member means the client
    // already holds this body. `*` matches whatever we have.
    let known = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.trim_start_matches("W/") == etag
            })
        });

    let mut response = if known {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, Body::from(asset.data)).into_response()
    };

    let mime = asset.metadata.mimetype();
    if let Ok(value) = HeaderValue::from_str(mime) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http::HeaderMap;

    /// The shell is the only thing that knows which assets the page needs, so
    /// the list comes from it rather than from a constant here. A `<link>` or
    /// `<script>` added to the page and not to `static/` renders a dashboard
    /// that is missing a piece and says nothing about it.
    #[test]
    fn every_asset_the_dashboard_references_is_embedded() {
        let shell = include_str!("../../static/index.html");

        let referenced: Vec<&str> = shell
            .match_indices("/static/")
            .map(|(at, _)| {
                let rest = &shell[at + "/static/".len()..];
                let end = rest
                    .find(['"', '\'', '?', '#', '>', ' '])
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();

        assert!(
            !referenced.is_empty(),
            "the shell should reference its assets by /static/ URL"
        );
        for name in referenced {
            assert!(get(name).is_some(), "{name} is referenced but not embedded");
        }
    }

    /// The assets are compiled in, not read from the working directory: this is
    /// the property `cargo install` depends on, and it is invisible from a
    /// checkout where `./static` happens to exist anyway. Reading through
    /// `CARGO_MANIFEST_DIR` rather than a relative path is what keeps this an
    /// assertion about the binary instead of about where the test was run.
    #[test]
    fn assets_are_compiled_in_rather_than_read_from_disk() {
        let on_disk = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("static")
            .join("index.html");
        let embedded = get("index.html").expect("index.html is embedded");

        assert_eq!(
            embedded.data.as_ref(),
            std::fs::read(&on_disk)
                .expect("the checkout has static/")
                .as_slice(),
            "the embedded shell drifted from the one in the tree"
        );
    }

    #[tokio::test]
    async fn serving_an_asset_carries_its_type_and_etag() {
        let response = serve(Path("storage.css".to_string()), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css"
        );
        let etag = response.headers().get(header::ETAG).unwrap().clone();
        assert!(
            etag.to_str().unwrap().starts_with('"'),
            "a strong ETag is quoted, got: {etag:?}"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty(), "the asset should have a body");
    }

    #[tokio::test]
    async fn a_matching_if_none_match_answers_304_without_the_body() {
        let first = serve(Path("storage.js".to_string()), HeaderMap::new()).await;
        let etag = first.headers().get(header::ETAG).unwrap().clone();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag.clone());
        let second = serve(Path("storage.js".to_string()), headers).await;

        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(second.headers().get(header::ETAG).unwrap(), &etag);
        let body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
        assert!(
            body.is_empty(),
            "a 304 carries no body, got {} bytes",
            body.len()
        );
    }

    /// A stale validator has to serve the new bytes, or a released CSS change
    /// would never reach a browser that still holds the old one.
    #[tokio::test]
    async fn a_stale_if_none_match_serves_the_asset() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"stale\""));

        let response = serve(Path("storage.js".to_string()), headers).await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unknown_asset_is_a_404() {
        let response = serve(Path("nope.css".to_string()), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// There is no filesystem behind the route, so a traversal attempt is just
    /// a path that was never embedded.
    #[tokio::test]
    async fn traversal_reaches_nothing() {
        let response = serve(Path("../Cargo.toml".to_string()), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
