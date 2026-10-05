//! Explicit 304 (Not Modified) cache-entry merge — usage explanation.
//!
//! reqwest does not implement an HTTP cache. Instead it ships a small,
//! pure building block for code that *does* keep its own cache:
//!
//! ```no_run
//! # async fn run() -> reqwest::Result<()> {
//! use bytes::Bytes;
//! use http::header::HeaderMap;
//! use reqwest::{merge_not_modified, CachedResponse, StatusCode};
//!
//! let client = reqwest::Client::new();
//!
//! // 1. The caller stores the original response itself.
//! let original = client.get("https://example.com/data").send().await?;
//! let stored = CachedResponse::new(
//!     original.status(),
//!     original.headers().clone(),
//!     original.bytes().await?,
//! );
//!
//! // 2. Later the caller performs a conditional request itself (here
//! //    shown with raw header access; reqwest does not retry or
//! //    revalidate automatically).
//! let validated = client.get("https://example.com/data").send().await?;
//! let status = validated.status();
//! let headers = validated.headers().clone();
//!
//! if status == StatusCode::NOT_MODIFIED {
//!     // 3. Merge explicitly. On error keep serving the old entry.
//!     let revalidation_request = HeaderMap::new();
//!     match merge_not_modified(status, &headers, &revalidation_request, &stored) {
//!         Ok(updated) => {
//!             // updated.body() is the original bytes, unchanged;
//!             // updated.headers() carries the merged end-to-end headers.
//!             let _body: &Bytes = updated.body();
//!         }
//!         Err(_e) => {
//!             // `stored` is untouched; keep serving it.
//!         }
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! What the merge guarantees (RFC 9111 section 4.3.4, plus extra checks):
//!
//! * only a real `304` is accepted;
//! * the cached body bytes are reused verbatim and are never replaced by
//!   the empty 304 body;
//! * a 304 `Content-Length` must match the cached body length, otherwise
//!   the merge fails and the stored entry stays exactly as it was (the
//!   header itself is never copied — it is framing for the unchanged
//!   body);
//! * hop-by-hop headers are removed: the RFC 9111 section 7.6.1 set
//!   (`connection`, `keep-alive`, `proxy-authenticate`,
//!   `proxy-authorization`, `te`, `trailer`, `transfer-encoding`,
//!   `upgrade`) plus every field named in the 304 `Connection` header;
//! * a changed `Vary` selection without the necessary request headers is
//!   rejected as `MissingVaryInfo`, and different values for a field both
//!   responses vary on are rejected independently as
//!   `VaryIdentityMismatch`;
//! * every other end-to-end header supplied by the 304 replaces the
//!   corresponding stored header; headers the 304 omits are preserved.
//!
//! This file is also a tiny offline runnable demonstration: run it with
//! `cargo run --example cache_revalidate`.

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE, ETAG};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
use reqwest::{merge_not_modified, CachedResponse};

fn main() {
    // The entry the caller cached from an earlier 200 response.
    let mut stored_headers = HeaderMap::new();
    stored_headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    stored_headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
    let stored = CachedResponse::new(StatusCode::OK, stored_headers, Bytes::from_static(b"abc"));

    // The 304 returned by the origin during (caller-driven) revalidation.
    let mut n304 = HeaderMap::new();
    n304.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
    n304.insert(ETAG, HeaderValue::from_static("\"v2\""));
    n304.insert(
        CONNECTION,
        HeaderValue::from_static("keep-alive, x-accel-buffering"),
    );
    n304.insert(KEEP_ALIVE, HeaderValue::from_static("timeout=5"));
    n304.insert("x-accel-buffering", HeaderValue::from_static("no"));

    let revalidation_request = HeaderMap::new();
    let merged = merge_not_modified(
        StatusCode::NOT_MODIFIED,
        &n304,
        &revalidation_request,
        &stored,
    )
    .expect("merge succeeds");

    // Body is still the original three bytes.
    assert_eq!(merged.body().as_ref(), b"abc");
    // Cache-Control was updated...
    assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=60");
    // ...Content-Type was preserved...
    assert_eq!(merged.headers()[CONTENT_TYPE], "text/plain");
    // ...and hop-by-hop headers never made it into the new entry.
    assert_eq!(merged.headers().get(CONNECTION), None);
    assert_eq!(merged.headers().get(KEEP_ALIVE), None);
    assert_eq!(
        merged
            .headers()
            .get(HeaderName::from_static("x-accel-buffering")),
        None
    );

    println!("merged body (unchanged): {:?}", merged.body());
    println!("merged headers:\n{:?}", merged.headers());

    // A 304 claiming a Content-Length that does not fit the cached body
    // is rejected; the old entry remains available untouched.
    let mut bad = HeaderMap::new();
    bad.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("9"));
    let err = merge_not_modified(
        StatusCode::NOT_MODIFIED,
        &bad,
        &revalidation_request,
        &stored,
    )
    .unwrap_err();
    println!("rejected mismatched Content-Length: {err}");
    assert_eq!(stored.body().as_ref(), b"abc");
}
