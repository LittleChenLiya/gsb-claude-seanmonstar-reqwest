//! Explicit 304 (Not Modified) cache-entry merge.
//!
//! This module is a **standalone, opt-in** building block for callers that
//! implement their own HTTP cache (RFC 9111). It performs exactly one
//! operation: updating a previously stored response with the end-to-end
//! header fields of a `304 Not Modified` validation response.
//!
//! It deliberately does **not**:
//!
//! * store, look up, or refresh entries automatically (no cache storage),
//! * send conditional requests or retry anything (no revalidation policy),
//! * modify ordinary responses such as the [`crate::Response`] type.
//!
//! The caller drives the whole cache lifecycle. [`merge_not_modified`] is
//! a pure function: it either returns a brand new, fully validated
//! [`CachedResponse`], or returns an error and the caller keeps serving
//! the previously stored entry unchanged (no partial merge is possible).
//!
//! # Merge rules
//!
//! Implements RFC 9111 section 4.3.4 ("Merging If the response status
//! code is 304 (Not Modified)"), with these extra safety checks:
//!
//! 1. The validation response MUST be exactly `304 Not Modified`.
//! 2. The `Vary` identity of the representation MUST still match the one
//!    captured when the entry was cached. If the 304 changes the `Vary`
//!    selection and the information needed to prove the identity is not
//!    available, the merge is rejected ([`MergeError::MissingVaryInfo`]);
//!    if the revalidation request carries different values for a selected
//!    field, it is rejected with [`MergeError::VaryIdentityMismatch`].
//! 3. A `Content-Length` on the 304 MUST equal the number of body bytes
//!    already stored; otherwise the merge is rejected and the old entry
//!    stays usable. `Content-Length` is never copied from the 304: it is
//!    message-framing metadata and the body does not change.
//! 4. Hop-by-hop header fields are never retained: the fields mandated by
//!    RFC 9111 section 7.6.1, plus every field nominated by the 304
//!    response `Connection` header (the `Connection` header itself
//!    included).
//! 5. On success the original body bytes are reused unchanged; only
//!    allowed end-to-end header fields of the stored response are replaced
//!    by the corresponding fields of the 304 response.

use bytes::Bytes;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, VARY,
};

/// `keep-alive` is a hop-by-hop field (RFC 9111 section 7.6.1) but has no
/// constant in the `http` crate.
fn keep_alive() -> HeaderName {
    HeaderName::from_static("keep-alive")
}
use http::StatusCode;

/// A stored response from a prior cacheable request.
///
/// This is a simple value type owned by the caller; reqwest never creates
/// or stores these automatically. The `body` is kept verbatim across a
/// 304 merge.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    /// Values of the request header fields selected by the original
    /// stored response `Vary` header, captured when the entry was cached.
    selecting_request_headers: HeaderMap,
}

impl CachedResponse {
    /// Create a cached entry from a stored status, headers and body.
    ///
    /// No freshness or cacheability computation is performed; the caller
    /// is responsible for only caching cacheable responses.
    pub fn new(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        CachedResponse {
            status,
            headers,
            body,
            selecting_request_headers: HeaderMap::new(),
        }
    }

    /// Attach the values of the request header fields named by the stored
    /// response `Vary` header, as captured from the request that produced
    /// the entry.
    ///
    /// These values are the "Vary identity" and are compared with the
    /// revalidation request during a 304 merge.
    pub fn with_selecting_request_headers(mut self, headers: HeaderMap) -> Self {
        self.selecting_request_headers = headers;
        self
    }

    /// The stored status code (never changed by a 304 merge).
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The stored response headers (the updated headers after a merge).
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The stored body bytes (identical bytes before and after a merge).
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Consumes the entry and returns its underlying body bytes.
    pub fn into_body(self) -> Bytes {
        self.body
    }

    /// The selecting request header values captured for `Vary`.
    pub fn selecting_request_headers(&self) -> &HeaderMap {
        &self.selecting_request_headers
    }
}

/// Error returned when a 304 response cannot be merged into a cached entry.
///
/// In every error case the caller MUST keep serving the previously stored
/// entry; [`merge_not_modified`] never performs a partial merge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MergeError {
    /// The validation response did not have status code 304.
    NotNotModified(StatusCode),

    /// A `Content-Length` value on the 304 could not be parsed.
    MalformedContentLength,

    /// The 304 `Content-Length` did not match the cached body length.
    ///
    /// Carries `(declared_length, cached_body_length)`.
    ContentLengthMismatch(u64, usize),

    /// The 304 changed the `Vary` selection (or used `Vary: *`) and the
    /// value of the named request header is not available, so it cannot be
    /// proven that the selected representation still matches.
    MissingVaryInfo(HeaderName),

    /// Values of a request header field selected by `Vary` differ between
    /// the original request and the revalidation request.
    VaryIdentityMismatch(HeaderName),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::NotNotModified(status) => write!(
                f,
                "expected a 304 Not Modified validation response, got {status}"
            ),
            MergeError::MalformedContentLength => {
                f.write_str("304 response has a malformed Content-Length header")
            }
            MergeError::ContentLengthMismatch(declared, actual) => write!(
                f,
                "304 Content-Length {declared} does not match the cached body of {actual} bytes"
            ),
            MergeError::MissingVaryInfo(name) => write!(
                f,
                "304 changed the Vary selection for request header `{name}`, whose value is unavailable"
            ),
            MergeError::VaryIdentityMismatch(name) => write!(
                f,
                "request header `{name}` selected by Vary differs from the cached identity"
            ),
        }
    }
}

impl std::error::Error for MergeError {}

/// Result of [`merge_not_modified`].
pub type MergeResult = Result<CachedResponse, MergeError>;

/// Hop-by-hop header fields listed by RFC 9111 section 7.6.1. These are
/// never retained on a merged entry, regardless of whether the 304
/// `Connection` header nominates them.
fn hop_by_hop() -> [HeaderName; 8] {
    [
        CONNECTION,
        keep_alive(),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ]
}

/// Update a cached entry with the header fields of a `304 Not Modified`
/// validation response.
///
/// `current_request_headers` are the headers of the revalidation request
/// that produced the 304; they are compared against the selecting headers
/// captured on the stored entry (see
/// [`CachedResponse::with_selecting_request_headers`]).
///
/// On success a **new** [`CachedResponse`] is returned: the cached body
/// bytes are reused unchanged and the allowed end-to-end stored header
/// fields are replaced by the 304 fields. On failure the error is
/// returned and the caller should keep using `stored` untouched.
///
/// See the [module documentation](self) for the exact validation rules.
pub fn merge_not_modified(
    status: StatusCode,
    not_modified_headers: &HeaderMap,
    current_request_headers: &HeaderMap,
    stored: &CachedResponse,
) -> MergeResult {
    // Rule 1: only 304 responses are merged.
    if status != StatusCode::NOT_MODIFIED {
        return Err(MergeError::NotNotModified(status));
    }

    // Rule 2: the Vary identity must remain provably unchanged.
    check_vary(stored, not_modified_headers, current_request_headers)?;

    // Rule 3: any Content-Length on the 304 must describe the cached body.
    if let Some(value) = not_modified_headers.get(CONTENT_LENGTH) {
        let declared = value
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .ok_or(MergeError::MalformedContentLength)?;
        let actual = stored.body.len() as u64;
        if declared != actual {
            return Err(MergeError::ContentLengthMismatch(
                declared,
                stored.body.len(),
            ));
        }
    }

    // Rule 4: gather every header field the 304 Connection header
    // nominates as hop-by-hop.
    let mut nominated = Vec::new();
    for value in not_modified_headers.get_all(CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                        nominated.push(name);
                    }
                }
            }
        }
    }

    fn is_hop_by_hop(name: &HeaderName, nominated: &[HeaderName]) -> bool {
        hop_by_hop().iter().any(|h| h == name) || nominated.iter().any(|h| h == name)
    }

    // Start from the stored headers, drop every hop-by-hop field (both the
    // standard ones and any Connection-nominated ones the stored entry may
    // have carried)...
    let mut merged = stored.headers.clone();
    for name in hop_by_hop() {
        merged.remove(name);
    }
    for name in &nominated {
        merged.remove(name);
    }

    // ...then replace every end-to-end stored field that the 304 supplies.
    // Content-Length is framing metadata for an unchanged body and is
    // never taken from the 304; hop-by-hop fields are filtered out.
    let mut previous: Option<HeaderName> = None;
    for (name, value) in not_modified_headers.iter() {
        let first_of_group = !matches!(&previous, Some(p) if p == name);
        previous = Some(name.clone());

        if name == CONTENT_LENGTH || is_hop_by_hop(name, &nominated) {
            continue;
        }
        if first_of_group {
            merged.remove(name);
        }
        merged.append(name, value.clone());
    }

    Ok(CachedResponse {
        status: stored.status,
        headers: merged,
        body: stored.body.clone(),
        selecting_request_headers: stored.selecting_request_headers.clone(),
    })
}

/// Parse the comma-separated header field names of every `Vary` value.
///
/// Returns [`MergeError::MissingVaryInfo`] for the wildcard `Vary: *`,
/// whose representation identity can never be re-proven.
fn parse_vary(headers: &HeaderMap) -> Result<Vec<HeaderName>, MergeError> {
    let mut names = Vec::new();
    for value in headers.get_all(VARY).iter() {
        let Ok(s) = value.to_str() else { continue };
        for token in s.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token == "*" {
                return Err(MergeError::MissingVaryInfo(VARY));
            }
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Validate the `Vary` identity across the stored response, the 304 and
/// the revalidation request.
fn check_vary(
    stored: &CachedResponse,
    not_modified_headers: &HeaderMap,
    current_request_headers: &HeaderMap,
) -> Result<(), MergeError> {
    let selected_old = parse_vary(&stored.headers)?;
    let selected_new = parse_vary(not_modified_headers)?;

    // A field newly selected by the 304 had no recorded original-request
    // value, so the identity cannot be proven for it.
    for name in &selected_new {
        if !selected_old.iter().any(|old| old == name) {
            return Err(MergeError::MissingVaryInfo(name.clone()));
        }
    }

    // Every selected field must have identical values in the original
    // request (captured on the entry) and the revalidation request.
    for name in selected_new {
        let old: Vec<&HeaderValue> = stored
            .selecting_request_headers
            .get_all(&name)
            .iter()
            .collect();
        let new: Vec<&HeaderValue> = current_request_headers.get_all(&name).iter().collect();

        if old.is_empty() {
            return Err(MergeError::MissingVaryInfo(name));
        }
        if old.len() != new.len() || old.iter().zip(new.iter()).any(|(a, b)| a != b) {
            return Err(MergeError::VaryIdentityMismatch(name));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_TYPE, ETAG, EXPIRES, LOCATION};

    fn cached_with_body(body: &'static str) -> CachedResponse {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        CachedResponse::new(StatusCode::OK, headers, Bytes::from_static(body.as_bytes()))
    }

    #[test]
    fn merge_updates_end_to_end_headers_but_keeps_body() {
        let stored = cached_with_body("abc");

        let mut n304 = HeaderMap::new();
        n304.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
        n304.insert(ETAG, HeaderValue::from_static("\"v2\""));
        let current = HeaderMap::new();

        let merged =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap();

        assert_eq!(merged.status(), StatusCode::OK);
        // The 304 replaces Cache-Control...
        assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=60");
        // ...adds a new end-to-end header...
        assert_eq!(merged.headers()[ETAG], "\"v2\"");
        // ...but leaves a header the 304 does not mention alone.
        assert_eq!(merged.headers()[CONTENT_TYPE], "text/plain");
        // The body bytes are untouched.
        assert_eq!(merged.body().as_ref(), b"abc");
        assert_eq!(merged.body().len(), 3);
    }

    #[test]
    fn matching_content_length_is_not_copied_and_body_stays() {
        let stored = cached_with_body("abc");

        let mut n304 = HeaderMap::new();
        n304.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));
        n304.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
        let current = HeaderMap::new();

        let merged =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap();
        assert_eq!(merged.body().as_ref(), b"abc");
        assert_eq!(merged.headers().get(CONTENT_LENGTH), None);
        assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=60");
    }

    #[test]
    fn conflicting_content_length_rejects_and_keeps_old_entry() {
        let stored = cached_with_body("abc");
        let old_cc = stored.headers()[CACHE_CONTROL].clone();

        let mut n304 = HeaderMap::new();
        n304.insert(CONTENT_LENGTH, HeaderValue::from_static("9"));
        n304.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=999"));
        let current = HeaderMap::new();

        let err =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap_err();
        assert_eq!(err, MergeError::ContentLengthMismatch(9, 3));

        // The old entry is completely unchanged.
        assert_eq!(stored.body().as_ref(), b"abc");
        assert_eq!(stored.headers()[CACHE_CONTROL], old_cc);
        assert_eq!(stored.headers().get(CONTENT_LENGTH), None);
    }

    #[test]
    fn malformed_content_length_is_rejected() {
        let stored = cached_with_body("abc");
        let mut n304 = HeaderMap::new();
        n304.insert(CONTENT_LENGTH, HeaderValue::from_static("nine"));
        let current = HeaderMap::new();
        let err =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap_err();
        assert_eq!(err, MergeError::MalformedContentLength);
    }

    #[test]
    fn connection_nominated_hop_fields_are_filtered() {
        let stored = cached_with_body("abc");

        let mut n304 = HeaderMap::new();
        // The 304 nominates both a standard hop field and a custom one.
        n304.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-accel-buffering"),
        );
        n304.insert(keep_alive(), HeaderValue::from_static("timeout=5"));
        n304.insert("x-accel-buffering", HeaderValue::from_static("no"));
        n304.insert(
            EXPIRES,
            HeaderValue::from_static("Thu, 01 Jan 2026 00:00:00 GMT"),
        );
        n304.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        let current = HeaderMap::new();

        let merged =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap();

        assert_eq!(merged.headers().get(CONNECTION), None);
        assert_eq!(merged.headers().get(keep_alive()), None);
        assert_eq!(merged.headers().get("x-accel-buffering"), None);
        assert_eq!(merged.headers().get(TRANSFER_ENCODING), None);
        // An end-to-end header is still merged.
        assert!(merged.headers().contains_key(EXPIRES));
        // The body survives.
        assert_eq!(merged.body().as_ref(), b"abc");
    }

    #[test]
    fn hop_fields_already_on_the_stored_entry_are_dropped() {
        let mut headers = HeaderMap::new();
        headers.insert(keep_alive(), HeaderValue::from_static("timeout=1"));
        headers.insert("x-accel-buffering", HeaderValue::from_static("yes"));
        let stored = CachedResponse::new(StatusCode::OK, headers, Bytes::from_static(b"abc"));

        let mut n304 = HeaderMap::new();
        n304.insert(CONNECTION, HeaderValue::from_static("x-accel-buffering"));
        let current = HeaderMap::new();

        let merged =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap();
        assert_eq!(merged.headers().get(keep_alive()), None);
        assert_eq!(merged.headers().get("x-accel-buffering"), None);
        assert_eq!(merged.headers().get(CONNECTION), None);
    }

    #[test]
    fn non_304_status_is_rejected() {
        let stored = cached_with_body("abc");
        let n304 = HeaderMap::new();
        let current = HeaderMap::new();
        let err = merge_not_modified(StatusCode::OK, &n304, &current, &stored).unwrap_err();
        assert_eq!(err, MergeError::NotNotModified(StatusCode::OK));
    }

    #[test]
    fn changed_vary_with_missing_info_is_rejected_independently() {
        // The stored response does not vary on Accept-Encoding...
        let stored = cached_with_body("abc");

        // ...but the 304 newly selects it, and no original value was
        // captured for it.
        let mut n304 = HeaderMap::new();
        n304.insert(VARY, HeaderValue::from_static("accept-encoding"));
        let current = HeaderMap::new();

        let err =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap_err();
        assert_eq!(
            err,
            MergeError::MissingVaryInfo(HeaderName::from_static("accept-encoding"))
        );
    }

    #[test]
    fn vary_star_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static("accept"));
        let stored = CachedResponse::new(StatusCode::OK, headers, Bytes::from_static(b"abc"))
            .with_selecting_request_headers(HeaderMap::new());

        let mut n304 = HeaderMap::new();
        n304.insert(VARY, HeaderValue::from_static("*"));
        let current = HeaderMap::new();
        let err =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap_err();
        assert!(matches!(err, MergeError::MissingVaryInfo(_)));
    }

    #[test]
    fn vary_identity_mismatch_is_detected() {
        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static("accept-encoding"));
        let mut original = HeaderMap::new();
        original.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let stored = CachedResponse::new(StatusCode::OK, headers, Bytes::from_static(b"abc"))
            .with_selecting_request_headers(original);

        let mut n304 = HeaderMap::new();
        n304.insert(VARY, HeaderValue::from_static("accept-encoding"));
        let mut current = HeaderMap::new();
        current.insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));

        let err =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap_err();
        assert_eq!(
            err,
            MergeError::VaryIdentityMismatch(HeaderName::from_static("accept-encoding"))
        );
    }

    #[test]
    fn vary_identity_match_passes() {
        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static("accept-encoding"));
        let mut original = HeaderMap::new();
        original.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let stored = CachedResponse::new(StatusCode::OK, headers, Bytes::from_static(b"abc"))
            .with_selecting_request_headers(original);

        let mut n304 = HeaderMap::new();
        n304.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
        let mut current = HeaderMap::new();
        current.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));

        let merged =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap();
        assert_eq!(merged.body().as_ref(), b"abc");
        assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=60");
    }

    #[test]
    fn merged_entry_is_a_new_value() {
        let stored = cached_with_body("abc");
        let n304 = HeaderMap::new();
        let current = HeaderMap::new();

        let merged =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304, &current, &stored).unwrap();
        // Same underlying body allocation (the bytes are not copied)...
        assert_eq!(merged.body().as_ptr(), stored.body().as_ptr());

        // ...and later merges do not leak headers into earlier entries.
        let mut n304_2 = HeaderMap::new();
        n304_2.insert(LOCATION, HeaderValue::from_static("/elsewhere"));
        let merged2 =
            merge_not_modified(StatusCode::NOT_MODIFIED, &n304_2, &current, &stored).unwrap();
        assert!(merged2.headers().contains_key(LOCATION));
        assert!(!merged.headers().contains_key(LOCATION));
    }
}
