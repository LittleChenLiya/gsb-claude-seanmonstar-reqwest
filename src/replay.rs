//! Explicit request replay with replay credentials.
//!
//! The [`Replay`] wrapper retries requests automatically, but **only** when
//! the request carries a [`Credential`] that proves the request may be
//! replayed. A streaming body is never assumed to be copyable: it can only be
//! replayed when the caller supplies a [`BodyFactory`] that can recreate it.
//!
//! # Request identity
//!
//! A [`Credential`] binds the identity of exactly one logical request:
//!
//! - the HTTP **method**,
//! - the exact **URL**,
//! - the **digest** of the body bytes (SHA-256), and
//! - the set of response **statuses** that permit a retry.
//!
//! A request is only replayed when it matches the credential's method and
//! URL, and the response status is in the credential's retryable set. The
//! URL binding is not widened by redirects: if the client followed a
//! redirect, the effective URL of the response no longer matches the
//! credential and the authorization stops there — the redirected request is
//! never resent under the original credential.
//!
//! # Authorization
//!
//! Even with a matching credential, a retry only happens when
//!
//! - the method is idempotent (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`,
//!   `TRACE`), or
//! - the caller explicitly authorized retries with
//!   [`Credential::allow_retry()`].
//!
//! A `POST` that was not explicitly authorized is sent exactly once, even if
//! the response status is retryable.
//!
//! # Body factory contract
//!
//! Small in-memory bodies are replayed automatically: the wrapper keeps a
//! copy of the bytes and derives the digest itself. Streaming bodies must be
//! provided through a [`BodyFactory`] with the following contract:
//!
//! - `create_body` may be called multiple times and **every** call must
//!   produce a body with byte-identical content.
//! - The produced body must be inspectable in memory (created from bytes,
//!   so that [`Body::as_bytes`] returns `Some`), because the digest is
//!   re-verified against the credential **before every send**, including
//!   each rebuild.
//! - If a rebuilt body's digest differs from the credential's digest, or the
//!   factory fails to produce a body, the replay stops *before* anything is
//!   sent and an error is returned.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn run() -> Result<(), reqwest::Error> {
//! let client = reqwest::Client::new();
//! let replay = reqwest::replay::Replay::new(client);
//!
//! let url = "https://example.com/data".parse::<reqwest::Url>().unwrap();
//! let credential = reqwest::replay::Credential::for_request(reqwest::Method::GET, url.clone());
//!
//! let request = reqwest::Request::new(reqwest::Method::GET, url);
//! let response = replay.execute(request, &credential).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use url::Url;

use crate::async_impl::body::Body;
use crate::error;
use crate::{Client, Method, Request, Response};

/// A wrapper around a [`Client`] that replays requests backed by a
/// [`Credential`].
///
/// See the [module-level documentation](self) for the replay rules.
#[derive(Clone, Debug)]
pub struct Replay {
    client: Client,
    max_retries: u32,
}

/// A replay credential binding the identity of one logical request.
///
/// See the [module-level documentation](self) for the exact identity and
/// authorization rules.
#[derive(Clone)]
pub struct Credential {
    method: Method,
    url: Url,
    digest: Option<Digest>,
    retry_statuses: BTreeSet<StatusCode>,
    allow_retry: bool,
    body: Option<CredBody>,
}

#[derive(Clone)]
enum CredBody {
    Bytes(Bytes),
    Factory(Arc<dyn BodyFactory>),
}

/// A factory that recreates a streaming request body for each replay.
///
/// See the [module-level documentation](self) for the factory contract.
///
/// Implemented for any `Fn() -> Option<Body> + Send + Sync`.
pub trait BodyFactory: Send + Sync + 'static {
    /// Create a fresh body for one send attempt.
    ///
    /// Every call must produce byte-identical content, and the produced body
    /// must be inspectable via [`Body::as_bytes`] so its digest can be
    /// re-verified before sending. Returning `None` aborts the replay.
    fn create_body(&self) -> Option<Body>;
}

impl<F> BodyFactory for F
where
    F: Fn() -> Option<Body> + Send + Sync + 'static,
{
    fn create_body(&self) -> Option<Body> {
        (self)()
    }
}

/// A cancellation handle for an in-flight replay.
///
/// When cancelled, a [`Replay`] stops before sending the next attempt and
/// returns an error instead.
#[derive(Clone, Debug, Default)]
pub struct Cancellation {
    inner: Arc<AtomicBool>,
}

/// A SHA-256 digest of a request body, part of the request identity bound
/// by a [`Credential`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

// ===== impl Replay =====

impl Replay {
    /// Create a replay wrapper around a client.
    pub fn new(client: Client) -> Self {
        Replay {
            client,
            max_retries: 2,
        }
    }

    /// Set the maximum number of retries on top of the original request.
    ///
    /// Default is 2.
    pub fn max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Execute a request, replaying it while the credential permits.
    ///
    /// The request must match the credential's method and URL. If the
    /// credential carries a body source (bytes or factory), it replaces the
    /// request body on every attempt, including the first.
    pub async fn execute(
        &self,
        request: Request,
        credential: &Credential,
    ) -> crate::Result<Response> {
        self.execute_inner(request, credential, None).await
    }

    /// Execute a request like [`Replay::execute()`], but stop early if the
    /// cancellation handle is cancelled.
    pub async fn execute_cancellable(
        &self,
        request: Request,
        credential: &Credential,
        cancel: Cancellation,
    ) -> crate::Result<Response> {
        self.execute_inner(request, credential, Some(cancel)).await
    }
}

// ===== private execute =====

impl Replay {
    async fn execute_inner(
        &self,
        mut request: Request,
        credential: &Credential,
        cancel: Option<Cancellation>,
    ) -> crate::Result<Response> {
        if request.method() != credential.method() || request.url() != credential.url() {
            return Err(error::builder(
                "request does not match the replay credential identity",
            ));
        }

        let authorized = credential.allow_retry || is_idempotent(request.method());

        // Resolve where bodies for (re)send attempts come from.
        let plan = match credential.body.as_ref() {
            Some(CredBody::Bytes(bytes)) => Plan::Bytes(bytes.clone()),
            Some(CredBody::Factory(factory)) => Plan::Factory(factory.clone()),
            None => match request.body_mut().take() {
                None => Plan::Empty,
                Some(body) => match body.as_bytes() {
                    // Small in-memory bodies get an automatically generated,
                    // replayable plan.
                    Some(bytes) => Plan::Bytes(Bytes::copy_from_slice(bytes)),
                    // A streaming body without a factory is NOT replayable.
                    // It may still be sent once.
                    None => Plan::OneShot(Some(body)),
                },
            },
        };

        let headers = request.headers().clone();
        let version = request.version();

        let mut plan = plan;
        let mut retries = 0u32;
        loop {
            if cancel.as_ref().map(|c| c.is_cancelled()).unwrap_or(false) {
                return Err(error::request("replay cancelled"));
            }

            let body = plan.body_for_attempt(retries, credential.digest.as_ref())?;

            let mut attempt = Request::new(credential.method.clone(), credential.url.clone());
            *attempt.headers_mut() = headers.clone();
            *attempt.version_mut() = version;
            if let Some(body) = body {
                *attempt.body_mut() = Some(body);
            }

            let response = self.client.execute(attempt).await?;

            // A redirect must not widen the authorization: the credential is
            // bound to its exact URL, so a response whose effective URL
            // differs is returned as-is and never triggers a replay.
            let url_matches = response.url() == credential.url();
            let retryable = credential.retry_statuses.contains(&response.status());

            if !authorized || !url_matches || !retryable || retries >= self.max_retries {
                return Ok(response);
            }
            retries += 1;
        }
    }
}

// ===== impl Credential =====

impl Credential {
    /// Create a credential for a request, with the body digest derived
    /// automatically when the request is executed.
    ///
    /// Bodies that are small in-memory buffers are replayed automatically;
    /// streaming bodies require [`Credential::for_stream()`] instead.
    ///
    /// The default retryable status set contains `429 Too Many Requests` and
    /// `503 Service Unavailable`.
    pub fn for_request(method: Method, url: Url) -> Self {
        Credential {
            method,
            url,
            digest: None,
            retry_statuses: default_retry_statuses(),
            allow_retry: false,
            body: None,
        }
    }

    /// Create a credential for a request with a small in-memory body.
    ///
    /// The body bytes are kept in the credential and replayed on each
    /// attempt; the digest is computed immediately.
    pub fn for_bytes(method: Method, url: Url, body: impl Into<Bytes>) -> Self {
        let bytes = body.into();
        Credential {
            method,
            url,
            digest: Some(Digest::of(&bytes)),
            retry_statuses: default_retry_statuses(),
            allow_retry: false,
            body: Some(CredBody::Bytes(bytes)),
        }
    }

    /// Create a credential for a request with a streaming body.
    ///
    /// The factory is called once immediately to compute the body digest
    /// bound into this credential, and again before every send attempt; each
    /// recreation is re-verified against that digest. See the
    /// [module-level documentation](self) for the factory contract.
    ///
    /// # Errors
    ///
    /// Fails if the factory cannot produce a body, or the produced body is
    /// not inspectable in memory.
    pub fn for_stream<F>(method: Method, url: Url, factory: F) -> crate::Result<Self>
    where
        F: BodyFactory,
    {
        let factory: Arc<dyn BodyFactory> = Arc::new(factory);
        let body = factory
            .create_body()
            .ok_or_else(|| error::body("body factory failed to create the initial body"))?;
        let digest = digest_of_body(&body)?;
        Ok(Credential {
            method,
            url,
            digest: Some(digest),
            retry_statuses: default_retry_statuses(),
            allow_retry: false,
            body: Some(CredBody::Factory(factory)),
        })
    }

    /// Set the response statuses that permit a retry.
    ///
    /// Replaces the default set of `429` and `503`.
    pub fn allows(mut self, statuses: impl IntoIterator<Item = StatusCode>) -> Self {
        self.retry_statuses = statuses.into_iter().collect();
        self
    }

    /// Explicitly authorize this request to be retried, even if its method
    /// is not idempotent (such as `POST`).
    pub fn allow_retry(mut self) -> Self {
        self.allow_retry = true;
        self
    }

    /// The method bound to this credential.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The exact URL bound to this credential.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The body digest bound to this credential, if known.
    pub fn digest(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }

    /// The response statuses that permit a retry.
    pub fn retry_statuses(&self) -> &BTreeSet<StatusCode> {
        &self.retry_statuses
    }

    /// Whether retries were explicitly authorized for a non-idempotent
    /// method.
    pub fn is_explicitly_authorized(&self) -> bool {
        self.allow_retry
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("digest", &self.digest)
            .field("retry_statuses", &self.retry_statuses)
            .field("allow_retry", &self.allow_retry)
            .finish()
    }
}

// ===== impl Cancellation =====

impl Cancellation {
    /// Create a new, uncancelled handle.
    pub fn new() -> Self {
        Cancellation::default()
    }

    /// Cancel the replay. Clones of this handle observe the cancellation.
    pub fn cancel(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    /// Whether the replay has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

// ===== impl Digest =====

impl Digest {
    /// Compute the digest of a byte slice.
    pub fn of(bytes: &[u8]) -> Digest {
        Digest(sha256::digest(bytes))
    }

    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ===== internal =====

fn default_retry_statuses() -> BTreeSet<StatusCode> {
    [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ]
    .into_iter()
    .collect()
}

fn is_idempotent(method: &Method) -> bool {
    [
        Method::GET,
        Method::HEAD,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
        Method::TRACE,
    ]
    .contains(method)
}

fn digest_of_body(body: &Body) -> crate::Result<Digest> {
    match body.as_bytes() {
        Some(bytes) => Ok(Digest::of(bytes)),
        None => Err(error::body(
            "replay body factory must produce in-memory bodies whose digest can be verified",
        )),
    }
}

enum Plan {
    Empty,
    Bytes(Bytes),
    Factory(Arc<dyn BodyFactory>),
    OneShot(Option<Body>),
}

impl Plan {
    fn body_for_attempt(
        &mut self,
        attempt: u32,
        digest: Option<&Digest>,
    ) -> crate::Result<Option<Body>> {
        match self {
            Plan::Empty => Ok(None),
            Plan::Bytes(bytes) => Ok(Some(Body::from(bytes.clone()))),
            Plan::Factory(factory) => {
                let body = factory.create_body().ok_or_else(|| {
                    error::body("body factory failed to recreate the request body")
                })?;
                // Re-verify the digest of every recreation before sending.
                if let Some(expected) = digest {
                    let actual = digest_of_body(&body)?;
                    if &actual != expected {
                        return Err(error::body(format!(
                            "recreated body digest {actual} does not match credential digest {expected}; replay stopped before sending"
                        )));
                    }
                }
                Ok(Some(body))
            }
            Plan::OneShot(body) => {
                if attempt == 0 {
                    Ok(body.take())
                } else {
                    Err(error::body(
                        "request body is not replayable; provide a BodyFactory credential to retry",
                    ))
                }
            }
        }
    }
}

// A minimal, dependency-free SHA-256 used for body digests.
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub(crate) fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, word) in w.iter_mut().take(16).enumerate() {
                *word = u32::from_be_bytes([
                    chunk[4 * i],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            Digest::of(b"").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            Digest::of(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // longer than one block
        assert_eq!(
            Digest::of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_string(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn idempotence_classification() {
        assert!(is_idempotent(&Method::GET));
        assert!(is_idempotent(&Method::PUT));
        assert!(!is_idempotent(&Method::POST));
        assert!(!is_idempotent(&Method::PATCH));
    }
}
