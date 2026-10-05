#![cfg(not(target_arch = "wasm32"))]
#![cfg(not(feature = "rustls-no-provider"))]
//! Loopback integration tests for the explicit 304 merge component.
//!
//! These tests use a real reqwest client against an in-process HTTP
//! server: one response is cached by hand, a second (304) response is
//! fetched over the loopback interface, and
//! `reqwest::merge_not_modified` is called explicitly. Nothing is cached
//! or retried automatically, and ordinary responses are never altered.

mod support;

use support::server;

use bytes::Bytes;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT_ENCODING, CACHE_CONTROL, CONNECTION, CONTENT_TYPE,
    ETAG,
};

use reqwest::{merge_not_modified, CachedResponse, MergeError, StatusCode};

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

/// Fetch `path` from `server` and describe the response as the raw
/// components required by the merge helper.
async fn fetch(
    client: &reqwest::Client,
    server: &server::Server,
    path: &str,
) -> (StatusCode, HeaderMap, Bytes) {
    let url = format!("http://{server_addr}{path}", server_addr = server.addr());
    let res = client.get(url).send().await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.bytes().await.unwrap();
    (status, headers, body)
}

#[tokio::test]
async fn loopback_304_merge_updates_headers_and_keeps_body() {
    // First origin response, which the caller caches by hand.
    let origin = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CACHE_CONTROL, "max-age=0")
            .body("abc".into())
            .unwrap()
    });

    // Validation response served over a real loopback connection.
    let validator = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(CACHE_CONTROL, "max-age=60")
            .header(ETAG, "\"v2\"")
            .body(reqwest::Body::default())
            .unwrap()
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let (status, headers, body) = fetch(&client, &origin, "/body").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "abc");
    let stored = CachedResponse::new(status, headers, body);

    let (status304, headers304, body304) = fetch(&client, &validator, "/validate").await;
    // reqwest performs no automatic caching or retry: the 304 is handed
    // to the caller as-is, with an empty body.
    assert_eq!(status304, StatusCode::NOT_MODIFIED);
    assert!(body304.is_empty());

    let current_request = HeaderMap::new();
    let merged = merge_not_modified(status304, &headers304, &current_request, &stored).unwrap();

    // The status stays the stored one...
    assert_eq!(merged.status(), StatusCode::OK);
    // ...end-to-end headers are updated...
    assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=60");
    assert_eq!(merged.headers()[ETAG], "\"v2\"");
    // ...untouched headers survive...
    assert_eq!(merged.headers()[CONTENT_TYPE], "text/plain");
    // ...and the original 3-byte body is kept verbatim.
    assert_eq!(merged.body().as_ref(), b"abc");
    assert_eq!(merged.body().len(), 3);

    // The previously stored entry is not modified by the merge.
    assert_eq!(stored.headers()[CACHE_CONTROL], "max-age=0");
    assert_eq!(stored.body().as_ref(), b"abc");
}

#[tokio::test]
async fn loopback_304_changed_vary_is_rejected_and_body_kept() {
    let origin = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .body("abc".into())
            .unwrap()
    });

    // The 304 newly varies on Accept-Encoding; no original value for it
    // was captured on the stored entry.
    let validator = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(CACHE_CONTROL, "max-age=60")
            .header(reqwest::header::VARY, "accept-encoding")
            .body(reqwest::Body::default())
            .unwrap()
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let (status, headers, body) = fetch(&client, &origin, "/body").await;
    let stored = CachedResponse::new(status, headers, body);

    let (status304, headers304, _body304) = fetch(&client, &validator, "/validate").await;
    assert_eq!(status304, StatusCode::NOT_MODIFIED);

    let current_request = HeaderMap::new();
    let err = merge_not_modified(status304, &headers304, &current_request, &stored).unwrap_err();
    assert_eq!(
        err,
        MergeError::MissingVaryInfo(HeaderName::from_static("accept-encoding"))
    );

    // The old entry is untouched, including the body bytes.
    assert_eq!(stored.body().as_ref(), b"abc");
    assert_eq!(stored.headers().get(CACHE_CONTROL), None);

    // An entry that originally varied on Accept-Encoding, revalidated
    // with a different value, gets the independent mismatch diagnosis.
    let origin_vary = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(reqwest::header::VARY, "accept-encoding")
            .body("abc".into())
            .unwrap()
    });
    let (status_v, headers_v, body_v) = fetch(&client, &origin_vary, "/vary-body").await;
    let mut original = HeaderMap::new();
    original.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    let stored_vary =
        CachedResponse::new(status_v, headers_v, body_v).with_selecting_request_headers(original);
    let mut current_request = HeaderMap::new();
    current_request.insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));
    let err =
        merge_not_modified(status304, &headers304, &current_request, &stored_vary).unwrap_err();
    assert_eq!(
        err,
        MergeError::VaryIdentityMismatch(HeaderName::from_static("accept-encoding"))
    );
}

#[tokio::test]
async fn loopback_304_filters_connection_nominated_hop_fields() {
    let origin = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(KEEP_ALIVE, "timeout=1")
            .body("abc".into())
            .unwrap()
    });

    // The 304 nominates hop-by-hop fields via its Connection header.
    let validator = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(CONNECTION, "keep-alive, x-accel-buffering")
            .header(KEEP_ALIVE, "timeout=5")
            .header("x-accel-buffering", "no")
            .header(CACHE_CONTROL, "max-age=30")
            .body(reqwest::Body::default())
            .unwrap()
    });

    let client = reqwest::Client::builder()
        .no_proxy()
        .connection_verbose(false)
        .build()
        .unwrap();

    let (status, headers, body) = fetch(&client, &origin, "/body").await;
    let stored = CachedResponse::new(status, headers, body);

    let (status304, headers304, _body304) = fetch(&client, &validator, "/validate").await;
    assert_eq!(status304, StatusCode::NOT_MODIFIED);

    // Whatever the transport preserved, the explicit merge must not
    // retain Connection or any hop field it nominated.
    let current_request = HeaderMap::new();
    let merged = merge_not_modified(status304, &headers304, &current_request, &stored).unwrap();
    assert_eq!(merged.headers().get(CONNECTION), None);
    assert_eq!(merged.headers().get(KEEP_ALIVE), None);
    assert_eq!(
        merged
            .headers()
            .get(HeaderName::from_static("x-accel-buffering")),
        None
    );
    // Allowed end-to-end headers are merged, and the body stays intact.
    assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=30");
    assert_eq!(merged.body().as_ref(), b"abc");
}

#[tokio::test]
async fn ordinary_response_is_not_modified_by_the_component() {
    // The component is opt-in: a normal 200 response fetched through the
    // client is returned exactly as sent, with no automatic caching.
    let origin = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CACHE_CONTROL, "max-age=0")
            .body("abc".into())
            .unwrap()
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (status, headers, body) = fetch(&client, &origin, "/plain").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[CONTENT_TYPE], "text/plain");
    assert_eq!(body, "abc");

    // Feeding a non-304 response to the merge component is rejected
    // explicitly rather than changing anything.
    let stored = CachedResponse::new(status, headers.clone(), body.clone());
    let current_request = HeaderMap::new();
    let err = merge_not_modified(status, &headers, &current_request, &stored).unwrap_err();
    assert_eq!(err, MergeError::NotNotModified(StatusCode::OK));
    assert_eq!(stored.body().as_ref(), b"abc");
}
