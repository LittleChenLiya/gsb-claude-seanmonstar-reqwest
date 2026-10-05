#![cfg(not(target_arch = "wasm32"))]
mod support;

use http::header::{CACHE_CONTROL, CONTENT_LENGTH, VARY};
use reqwest::cache::{merge_not_modified, CachedResponse, MergeError};
use reqwest::Client;

/// Build a cached entry from a 200 response served by the loopback server.
async fn fetch_cached(client: &Client, url: &str) -> CachedResponse {
    let res = client
        .get(url)
        .header("X-Test", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let headers = res.headers().clone();
    let body = res.bytes().await.unwrap();
    let mut vary_headers = http::HeaderMap::new();
    vary_headers.insert("X-Test", "1".parse().unwrap());
    CachedResponse::with_vary_headers(headers, body, vary_headers)
}

/// Loopback: a 304 updates Cache-Control, keeps the body, and filters
/// nominated hop-by-hop fields.
#[tokio::test]
async fn loopback_304_merge_updates_headers_keeps_body() {
    let server = support::server::http(move |req| async move {
        if req.headers().contains_key("if-none-match") {
            // Revalidation: 304 with a fresh Cache-Control, a matching
            // Content-Length, and a nominated hop field that must be
            // filtered out.
            http::Response::builder()
                .status(304)
                .header(CACHE_CONTROL, "max-age=200")
                .header(CONTENT_LENGTH, "3")
                .header(VARY, "X-Test")
                .header("Connection", "X-Merge-Test")
                .header("X-Merge-Test", "should-drop")
                .body(reqwest::Body::from(""))
                .unwrap()
        } else {
            http::Response::builder()
                .status(200)
                .header(CACHE_CONTROL, "max-age=100")
                .header(CONTENT_LENGTH, "3")
                .header(VARY, "X-Test")
                .header("ETag", "\"v1\"")
                .body(reqwest::Body::from("abc"))
                .unwrap()
        }
    });

    let url = format!("http://{}/item", server.addr());
    let client = Client::builder().no_proxy().build().unwrap();

    let cached = fetch_cached(&client, &url).await;

    // Revalidate: the server answers with a 304.
    let res = client
        .get(&url)
        .header("X-Test", "1")
        .header("If-None-Match", "\"v1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);

    let mut request_headers = http::HeaderMap::new();
    request_headers.insert("X-Test", "1".parse().unwrap());

    let merged = merge_not_modified(
        &cached,
        res.status(),
        res.headers(),
        Some(&request_headers),
    )
    .unwrap();

    // Body bytes are unchanged.
    assert_eq!(&merged.body()[..], b"abc");
    // The 304's end-to-end headers are applied.
    assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=200");
    assert_eq!(merged.headers()[CONTENT_LENGTH], "3");
    assert_eq!(merged.headers()[VARY], "X-Test");
    // Nominated hop-by-hop fields are filtered.
    assert!(!merged.headers().contains_key("x-merge-test"));
    assert!(!merged.headers().contains_key("connection"));
    // The original entry is untouched.
    assert_eq!(&cached.body()[..], b"abc");
    assert_eq!(cached.headers()[CACHE_CONTROL], "max-age=100");
}

/// Loopback: a 304 whose Content-Length disagrees with the cached body is
/// rejected and the cached entry is left unchanged.
#[tokio::test]
async fn loopback_304_content_length_mismatch_keeps_entry() {
    let server = support::server::http(move |req| async move {
        if req.headers().contains_key("if-none-match") {
            // A 304 with a (technically invalid) body so that the
            // Content-Length header is actually sent; the merge only
            // inspects headers, so the body is irrelevant.
            http::Response::builder()
                .status(304)
                .header(CACHE_CONTROL, "max-age=200")
                .header(CONTENT_LENGTH, "9")
                .body(reqwest::Body::from("123456789"))
                .unwrap()
        } else {
            http::Response::builder()
                .status(200)
                .header(CACHE_CONTROL, "max-age=100")
                .body(reqwest::Body::from("abc"))
                .unwrap()
        }
    });

    let url = format!("http://{}/item", server.addr());
    let client = Client::builder().no_proxy().build().unwrap();

    let res = client.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let cached = CachedResponse::new(res.headers().clone(), res.bytes().await.unwrap());

    let res = client
        .get(&url)
        .header("If-None-Match", "\"v1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);

    let err = merge_not_modified(&cached, res.status(), res.headers(), None).unwrap_err();

    assert_eq!(
        err,
        MergeError::ContentLengthMismatch {
            cached: 3,
            received: 9,
        }
    );
    // The cached entry is unchanged.
    assert_eq!(&cached.body()[..], b"abc");
    assert_eq!(cached.headers()[CACHE_CONTROL], "max-age=100");
}

/// Loopback: a 304 that changes Vary is rejected with the distinct Vary
/// diagnostic when the new request's header values are missing.
#[tokio::test]
async fn loopback_304_vary_change_without_request_headers_rejected() {
    let server = support::server::http(move |req| async move {
        if req.headers().contains_key("if-none-match") {
            http::Response::builder()
                .status(304)
                .header(CACHE_CONTROL, "max-age=200")
                .header(VARY, "X-Test, X-Other")
                .body(reqwest::Body::from(""))
                .unwrap()
        } else {
            http::Response::builder()
                .status(200)
                .header(CACHE_CONTROL, "max-age=100")
                .header(VARY, "X-Test")
                .body(reqwest::Body::from("abc"))
                .unwrap()
        }
    });

    let url = format!("http://{}/item", server.addr());
    let client = Client::builder().no_proxy().build().unwrap();

    let cached = fetch_cached(&client, &url).await;

    let res = client
        .get(&url)
        .header("X-Test", "1")
        .header("If-None-Match", "\"v1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);

    // No request header values supplied: the Vary change cannot be
    // re-verified, so the merge is rejected with the distinct diagnostic.
    let err = merge_not_modified(&cached, res.status(), res.headers(), None).unwrap_err();

    assert!(matches!(err, MergeError::VaryIdentityChanged(_)));
    assert!(!matches!(err, MergeError::ContentLengthMismatch { .. }));
    // The cached entry is unchanged.
    assert_eq!(&cached.body()[..], b"abc");
    assert_eq!(cached.headers()[VARY], "X-Test");
}
