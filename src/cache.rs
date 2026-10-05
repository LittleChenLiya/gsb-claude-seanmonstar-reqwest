//! Explicit merging of `304 Not Modified` responses into cached responses.
//!
//! This module provides a single, explicit operation: merge a fresh
//! `304 Not Modified` response into a previously stored cache entry.
//! It does **not** implement automatic caching, revalidation, or retries,
//! and it never modifies the normal [`Response`](crate::Response) type.
//!
//! # Merge rules
//!
//! - Only end-to-end header fields from the 304 are applied. Hop-by-hop
//!   fields — the standard hop-by-hop set plus any field nominated by the
//!   304 response's `Connection` header — are filtered out and never
//!   retained.
//! - The cached body bytes are never modified.
//! - If the 304 carries a `Content-Length`, it must equal the cached
//!   body length; otherwise the merge is rejected and the cached entry is
//!   left unchanged.
//! - If the 304's `Vary` differs from the cached entry's, the new
//!   request's header values are required to re-verify identity. If they
//!   are missing, or do not match the cached identity, the merge is
//!   rejected with [`MergeError::VaryIdentityChanged`].
//! - Only when every check passes is a new [`CachedResponse`] returned.
//!
//! # Example
//!
//! ```
//! use reqwest::cache::{merge_not_modified, CachedResponse};
//! use http::header::{CACHE_CONTROL, CONTENT_LENGTH};
//! use http::{HeaderMap, StatusCode};
//! use bytes::Bytes;
//!
//! let cached = CachedResponse::new(HeaderMap::new(), Bytes::from_static(b"abc"));
//!
//! let mut not_modified = HeaderMap::new();
//! not_modified.insert(CACHE_CONTROL, "max-age=200".parse().unwrap());
//! not_modified.insert(CONTENT_LENGTH, "3".parse().unwrap());
//!
//! let merged = merge_not_modified(
//!     &cached,
//!     StatusCode::NOT_MODIFIED,
//!     &not_modified,
//!     None,
//! )
//! .unwrap();
//! assert_eq!(&merged.body()[..], b"abc");
//! assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=200");
//! ```

use std::collections::HashSet;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::StatusCode;

/// A stored cache entry: response headers plus the original body bytes.
///
/// The body bytes are never modified by merging; a successful merge
/// returns a new entry with updated headers but the same body.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    headers: HeaderMap,
    body: Bytes,
    /// Request header values that determine this entry's identity (the
    /// fields listed in the response's `Vary` header).
    vary_headers: HeaderMap,
}

impl CachedResponse {
    /// Create a cached entry with no stored vary identity.
    pub fn new(headers: HeaderMap, body: Bytes) -> Self {
        CachedResponse {
            headers,
            body,
            vary_headers: HeaderMap::new(),
        }
    }

    /// Create a cached entry that also stores the request header values
    /// its identity depends on (see `Vary`).
    pub fn with_vary_headers(
        headers: HeaderMap,
        body: Bytes,
        vary_headers: HeaderMap,
    ) -> Self {
        CachedResponse {
            headers,
            body,
            vary_headers,
        }
    }

    /// The stored response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The original body bytes.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The request header values this entry's identity depends on.
    pub fn vary_headers(&self) -> &HeaderMap {
        &self.vary_headers
    }

    /// Consume the entry and return its parts.
    pub fn into_parts(self) -> (HeaderMap, Bytes, HeaderMap) {
        (self.headers, self.body, self.vary_headers)
    }
}

/// An error that prevents a 304 from being merged into a cached entry.
///
/// When a merge fails, the cached entry is left unchanged; only an
/// error is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// The provided status was not `304 Not Modified`.
    NotModified,
    /// The 304's `Content-Length` could not be parsed.
    InvalidContentLength(HeaderValue),
    /// The 304's `Content-Length` disagrees with the cached body length.
    ContentLengthMismatch {
        /// The cached body length in bytes.
        cached: u64,
        /// The length declared by the 304.
        received: u64,
    },
    /// The `Vary` identity changed and could not be re-verified.
    ///
    /// This is a distinct diagnostic: a `Vary` problem never manifests
    /// as a content-length problem or a generic merge failure.
    VaryIdentityChanged(VaryIdentityError),
}

/// Detail for a [`MergeError::VaryIdentityChanged`] rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaryIdentityError {
    /// The cached entry's `Vary` header, if any.
    pub cached: Option<HeaderValue>,
    /// The 304's `Vary` header.
    pub received: HeaderValue,
    /// Why the identity could not be re-verified.
    pub reason: VaryReason,
}

/// Why a `Vary` identity could not be re-verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaryReason {
    /// The new request's header values were not supplied.
    MissingRequestHeaders,
    /// The new request is missing values for fields the new `Vary`
    /// depends on.
    MissingFields(Vec<HeaderName>),
    /// The new request's values differ from the cached identity.
    MismatchedFields(Vec<(HeaderName, HeaderValue, HeaderValue)>),
    /// The `Vary` value cannot be re-verified (e.g. `*` or non-ASCII).
    Unverifiable,
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::NotModified => write!(f, "status is not 304 Not Modified"),
            MergeError::InvalidContentLength(v) => {
                write!(f, "invalid Content-Length in 304: {:?}", v)
            }
            MergeError::ContentLengthMismatch { cached, received } => write!(
                f,
                "Content-Length mismatch: cached body is {} bytes, 304 declares {}",
                cached, received
            ),
            MergeError::VaryIdentityChanged(err) => {
                write!(f, "Vary identity changed: {}", err.reason)
            }
        }
    }
}

impl std::fmt::Display for VaryReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaryReason::MissingRequestHeaders => {
                write!(f, "new request header values were not supplied")
            }
            VaryReason::MissingFields(fields) => {
                write!(f, "new request is missing fields: {:?}", fields)
            }
            VaryReason::MismatchedFields(fields) => {
                write!(
                    f,
                    "new request values differ from cached identity: {:?}",
                    fields
                )
            }
            VaryReason::Unverifiable => write!(f, "Vary value cannot be re-verified"),
        }
    }
}

impl std::error::Error for MergeError {}

/// Merge a `304 Not Modified` response into a cached entry.
///
/// `status` and `not_modified` describe the fresh 304 response.
/// `request_headers` are the new request's header values, used to
/// re-verify `Vary` identity when the 304 changes it; pass `None` to
/// skip re-verification (a changed `Vary` will then be rejected).
///
/// On success, a new [`CachedResponse`] is returned with the 304's
/// end-to-end headers applied and the original body bytes unchanged.
/// On failure, [`MergeError`] is returned and the cached entry is
/// untouched.
pub fn merge_not_modified(
    cached: &CachedResponse,
    status: StatusCode,
    not_modified: &HeaderMap,
    request_headers: Option<&HeaderMap>,
) -> Result<CachedResponse, MergeError> {
    if status != StatusCode::NOT_MODIFIED {
        return Err(MergeError::NotModified);
    }

    // Hop-by-hop headers are never retained, including fields nominated
    // by the 304's `Connection` header.
    let filtered = filter_hop_by_hop(not_modified);

    // Content-Length, if present, must agree with the cached body.
    if let Some(value) = filtered.get(header::CONTENT_LENGTH) {
        let received = parse_content_length(value)?;
        let cached_len = cached.body.len() as u64;
        if received != cached_len {
            return Err(MergeError::ContentLengthMismatch {
                cached: cached_len,
                received,
            });
        }
    }

    // Vary identity must be re-verified against the new request.
    let new_vary = filtered.get(header::VARY);
    match (cached.headers.get(header::VARY), new_vary) {
        (None, None) => {}
        (Some(old), Some(new)) if old == new => {
            verify_vary_fields(cached, Some(old), new, request_headers, false)?;
        }
        (old, Some(new)) => {
            // Identity changed (or newly declared): the new request's
            // header values are required to re-verify identity.
            verify_vary_fields(cached, old, new, request_headers, true)?;
        }
        (Some(old), None) => {
            // The 304 drops Vary: keep the cached identity and verify
            // the new request against it.
            verify_vary_fields(cached, Some(old), old, request_headers, false)?;
        }
    }

    // Apply the 304's end-to-end headers on top of the cached ones,
    // replacing any existing values. The body is carried over unchanged.
    let mut headers = cached.headers.clone();
    for name in filtered.keys() {
        headers.remove(name);
        for value in filtered.get_all(name) {
            headers.append(name.clone(), value.clone());
        }
    }

    Ok(CachedResponse {
        headers,
        body: cached.body.clone(),
        vary_headers: cached.vary_headers.clone(),
    })
}

/// Returns true if `name` is a standard hop-by-hop header field
/// (RFC 9110 §7.6.1).
fn is_standard_hop_by_hop(name: &HeaderName) -> bool {
    *name == header::CONNECTION
        || *name == header::PROXY_AUTHENTICATE
        || *name == header::PROXY_AUTHORIZATION
        || *name == header::TE
        || *name == header::TRAILER
        || *name == header::TRANSFER_ENCODING
        || *name == header::UPGRADE
        || name == "keep-alive"
}

fn filter_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated(headers);
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        let is_hop = is_standard_hop_by_hop(name) || nominated.contains(name);
        if !is_hop {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

fn connection_nominated(headers: &HeaderMap) -> HashSet<HeaderName> {
    let mut set = HashSet::new();
    for value in headers.get_all(header::CONNECTION) {
        if let Ok(s) = value.to_str() {
            for part in s.split(',') {
                if let Ok(name) = HeaderName::from_bytes(part.trim().as_bytes()) {
                    set.insert(name);
                }
            }
        }
    }
    set
}

fn parse_content_length(value: &HeaderValue) -> Result<u64, MergeError> {
    value
        .to_str()
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or_else(|| MergeError::InvalidContentLength(value.clone()))
}

/// Verify that the new request's header values match the cached identity
/// for the fields listed in `new_vary`.
///
/// If `request_headers` is `None` and `reject_if_missing` is set, the
/// merge is rejected (identity changed with no way to re-verify). If
/// `request_headers` is `None` and `reject_if_missing` is unset, the
/// check is skipped (identity is assumed unchanged).
fn verify_vary_fields(
    cached: &CachedResponse,
    old_vary: Option<&HeaderValue>,
    new_vary: &HeaderValue,
    request_headers: Option<&HeaderMap>,
    reject_if_missing: bool,
) -> Result<(), MergeError> {
    let request_headers = match request_headers {
        Some(headers) => headers,
        None if reject_if_missing => {
            return Err(MergeError::VaryIdentityChanged(VaryIdentityError {
                cached: old_vary.cloned(),
                received: new_vary.clone(),
                reason: VaryReason::MissingRequestHeaders,
            }));
        }
        None => return Ok(()),
    };

    let value_str = match new_vary.to_str() {
        Ok(s) => s,
        Err(_) => {
            return Err(MergeError::VaryIdentityChanged(VaryIdentityError {
                cached: old_vary.cloned(),
                received: new_vary.clone(),
                reason: VaryReason::Unverifiable,
            }));
        }
    };

    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    for field in value_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if field == "*" {
            return Err(MergeError::VaryIdentityChanged(VaryIdentityError {
                cached: old_vary.cloned(),
                received: new_vary.clone(),
                reason: VaryReason::Unverifiable,
            }));
        }
        let name = match HeaderName::from_bytes(field.as_bytes()) {
            Ok(name) => name,
            Err(_) => continue,
        };
        match request_headers.get(&name) {
            None => missing.push(name),
            Some(received_value) => {
                if let Some(cached_value) = cached.vary_headers.get(&name) {
                    if received_value != cached_value {
                        mismatched.push((
                            name,
                            cached_value.clone(),
                            received_value.clone(),
                        ));
                    }
                }
            }
        }
    }

    if !missing.is_empty() {
        return Err(MergeError::VaryIdentityChanged(VaryIdentityError {
            cached: old_vary.cloned(),
            received: new_vary.clone(),
            reason: VaryReason::MissingFields(missing),
        }));
    }
    if !mismatched.is_empty() {
        return Err(MergeError::VaryIdentityChanged(VaryIdentityError {
            cached: old_vary.cloned(),
            received: new_vary.clone(),
            reason: VaryReason::MismatchedFields(mismatched),
        }));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{CACHE_CONTROL, CONTENT_LENGTH, ETAG, VARY};

    fn cached_body() -> Bytes {
        Bytes::from_static(b"abc")
    }

    #[test]
    fn updates_cache_control_keeps_body() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, "max-age=100".parse().unwrap());
        let cached = CachedResponse::new(headers, cached_body());

        let mut not_modified = HeaderMap::new();
        not_modified.insert(CACHE_CONTROL, "max-age=200".parse().unwrap());

        let merged = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            None,
        )
        .unwrap();

        assert_eq!(&merged.body()[..], b"abc");
        assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=200");
        // The original entry is untouched.
        assert_eq!(cached.headers()[CACHE_CONTROL], "max-age=100");
    }

    #[test]
    fn content_length_mismatch_rejects_and_keeps_entry() {
        let cached = CachedResponse::new(HeaderMap::new(), cached_body());

        let mut not_modified = HeaderMap::new();
        not_modified.insert(CONTENT_LENGTH, "9".parse().unwrap());

        let err = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            None,
        )
        .unwrap_err();

        assert_eq!(
            err,
            MergeError::ContentLengthMismatch {
                cached: 3,
                received: 9,
            }
        );
        // The cached entry is unchanged.
        assert_eq!(&cached.body()[..], b"abc");
        assert!(!cached.headers().contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn nominated_hop_fields_are_filtered() {
        let cached = CachedResponse::new(HeaderMap::new(), cached_body());

        let mut not_modified = HeaderMap::new();
        not_modified.insert(CACHE_CONTROL, "max-age=200".parse().unwrap());
        not_modified.insert(CONTENT_LENGTH, "3".parse().unwrap());
        not_modified
            .insert(header::CONNECTION, "X-Foo, Keep-Alive".parse().unwrap());
        not_modified.insert("X-Foo", "bar".parse().unwrap());
        not_modified.insert("keep-alive", "timeout=5".parse().unwrap());
        not_modified
            .insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());

        let merged = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            None,
        )
        .unwrap();

        assert_eq!(&merged.body()[..], b"abc");
        assert_eq!(merged.headers()[CACHE_CONTROL], "max-age=200");
        assert!(!merged.headers().contains_key(header::CONNECTION));
        assert!(!merged.headers().contains_key("keep-alive"));
        assert!(!merged
            .headers()
            .contains_key(header::TRANSFER_ENCODING));
        assert!(!merged.headers().contains_key("X-Foo"));
    }

    #[test]
    fn vary_change_without_request_headers_is_rejected() {
        let mut cached_headers = HeaderMap::new();
        cached_headers.insert(VARY, "Accept-Encoding".parse().unwrap());
        let mut vary_headers = HeaderMap::new();
        vary_headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let cached = CachedResponse::with_vary_headers(
            cached_headers,
            cached_body(),
            vary_headers,
        );

        let mut not_modified = HeaderMap::new();
        not_modified
            .insert(VARY, "Accept-Encoding, X-Test".parse().unwrap());

        let err = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MergeError::VaryIdentityChanged(VaryIdentityError {
                reason: VaryReason::MissingRequestHeaders,
                ..
            })
        ));
        // Distinct from a content-length diagnostic.
        assert!(!matches!(err, MergeError::ContentLengthMismatch { .. }));
    }

    #[test]
    fn vary_change_with_matching_request_headers_merges() {
        let mut cached_headers = HeaderMap::new();
        cached_headers.insert(VARY, "Accept-Encoding".parse().unwrap());
        let mut vary_headers = HeaderMap::new();
        vary_headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let cached = CachedResponse::with_vary_headers(
            cached_headers,
            cached_body(),
            vary_headers,
        );

        let mut not_modified = HeaderMap::new();
        not_modified
            .insert(VARY, "Accept-Encoding, X-Test".parse().unwrap());

        let mut request_headers = HeaderMap::new();
        request_headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        request_headers.insert("X-Test", "1".parse().unwrap());

        let merged = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            Some(&request_headers),
        )
        .unwrap();

        assert_eq!(merged.headers()[VARY], "Accept-Encoding, X-Test");
    }

    #[test]
    fn vary_change_with_mismatched_request_headers_is_rejected() {
        let mut cached_headers = HeaderMap::new();
        cached_headers.insert(VARY, "Accept-Encoding".parse().unwrap());
        let mut vary_headers = HeaderMap::new();
        vary_headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let cached = CachedResponse::with_vary_headers(
            cached_headers,
            cached_body(),
            vary_headers,
        );

        let mut not_modified = HeaderMap::new();
        not_modified.insert(VARY, "Accept-Encoding".parse().unwrap());

        let mut request_headers = HeaderMap::new();
        request_headers
            .insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

        let err = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            Some(&request_headers),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MergeError::VaryIdentityChanged(VaryIdentityError {
                reason: VaryReason::MismatchedFields(_),
                ..
            })
        ));
    }

    #[test]
    fn vary_unchanged_with_matching_request_merges() {
        let mut cached_headers = HeaderMap::new();
        cached_headers.insert(VARY, "Accept-Encoding".parse().unwrap());
        let mut vary_headers = HeaderMap::new();
        vary_headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let cached = CachedResponse::with_vary_headers(
            cached_headers,
            cached_body(),
            vary_headers,
        );

        let mut not_modified = HeaderMap::new();
        not_modified.insert(VARY, "Accept-Encoding".parse().unwrap());

        let mut request_headers = HeaderMap::new();
        request_headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let merged = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            Some(&request_headers),
        )
        .unwrap();

        assert_eq!(merged.headers()[VARY], "Accept-Encoding");
        assert_eq!(&merged.body()[..], b"abc");
    }

    #[test]
    fn non_304_status_is_rejected() {
        let cached = CachedResponse::new(HeaderMap::new(), cached_body());
        let err = merge_not_modified(
            &cached,
            StatusCode::OK,
            &HeaderMap::new(),
            None,
        )
        .unwrap_err();
        assert_eq!(err, MergeError::NotModified);
    }

    #[test]
    fn etag_and_other_end_to_end_headers_apply() {
        let cached = CachedResponse::new(HeaderMap::new(), cached_body());

        let mut not_modified = HeaderMap::new();
        not_modified.insert(ETAG, "\"v2\"".parse().unwrap());

        let merged = merge_not_modified(
            &cached,
            StatusCode::NOT_MODIFIED,
            &not_modified,
            None,
        )
        .unwrap();

        assert_eq!(merged.headers()[ETAG], "\"v2\"");
        assert_eq!(&merged.body()[..], b"abc");
    }
}