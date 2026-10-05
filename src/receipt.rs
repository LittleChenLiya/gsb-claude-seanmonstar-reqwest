//! Explicit per-request receipts.
//!
//! A receipt records exactly how far a single request got:
//!
//! 1. [`Phase::Build`] -- the request was being constructed.
//! 2. [`Phase::AwaitHeaders`] -- the request was sent while waiting for the
//!    response headers to arrive (this includes DNS, TLS and the TCP
//!    connection; those internal stages are intentionally not guessed).
//! 3. [`Phase::ConsumeBody`] -- response headers were received and the body
//!    is being consumed.
//! 4. [`Phase::Complete`] -- the body reached a full, clean EOF.
//!
//! Getting a [`crate::Response`] does **not** mean the body has
//! finished; a response is produced as soon as the headers arrive.
//!
//! The receipt is opt-in via [`RequestBuilder::send_with_receipt`] and never
//! changes the behaviour of the default [`crate::Client`].
//!
//! # Privacy
//!
//! A receipt only ever stores the *category* of the requested URL -- its
//! scheme and host (and port), i.e. the URL authority -- never the path,
//! query, fragment or any header value. Errors attached to a receipt have
//! their URL stripped for the same reason.

#![cfg_attr(docsrs, doc(cfg(feature = "receipts")))]

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::Body as HttpBody;
use pin_project_lite::pin_project;

use crate::async_impl::body::ResponseBody;
use crate::async_impl::request::RequestBuilder;
use crate::{Error, Response, StatusCode, Url};

/// Defensive fallback used only when a builder error carries no URL at all.
pub(crate) fn fallback_url() -> &'static Url {
    use std::sync::OnceLock;
    static FALLBACK: OnceLock<Url> = OnceLock::new();
    FALLBACK.get_or_init(|| Url::parse("http://invalid/").unwrap())
}

// Phase values stored atomically.
const PHASE_BUILD: u8 = 0;
const PHASE_AWAIT_HEADERS: u8 = 1;
const PHASE_CONSUME_BODY: u8 = 2;
const PHASE_COMPLETE: u8 = 3;

/// The phase of a request that a receipt is describing.
///
/// This describes the *external* lifecycle of a request. Internal transport
/// stages such as DNS resolution or the TLS handshake are not guessed; if they
/// fail they are reported as a failure while [`Phase::AwaitHeaders`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// The request was being built, before it was sent.
    Build,
    /// The request was sent while waiting for the response headers.
    ///
    /// Connection establishment, DNS and TLS all happen inside this phase;
    /// they are not reported separately.
    AwaitHeaders,
    /// The response headers were received and the body was being consumed.
    ConsumeBody,
    /// The response body reached a complete, clean EOF.
    Complete,
}

impl Phase {
    fn from_u8(value: u8) -> Phase {
        match value {
            PHASE_AWAIT_HEADERS => Phase::AwaitHeaders,
            PHASE_CONSUME_BODY => Phase::ConsumeBody,
            PHASE_COMPLETE => Phase::Complete,
            _ => Phase::Build,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Phase::Build => PHASE_BUILD,
            Phase::AwaitHeaders => PHASE_AWAIT_HEADERS,
            Phase::ConsumeBody => PHASE_CONSUME_BODY,
            Phase::Complete => PHASE_COMPLETE,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Build => "build",
            Phase::AwaitHeaders => "await-headers",
            Phase::ConsumeBody => "consume-body",
            Phase::Complete => "complete",
        })
    }
}

/// The terminal outcome recorded by a [`RequestReceipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The request failed. See [`RequestReceipt::error`] and
    /// [`RequestReceipt::phase`] for where it failed and why.
    Failed,
    /// The response was dropped before its body was fully consumed.
    ///
    /// This is not an error: no error was observed, but the body was never
    /// read to EOF.
    Incomplete,
    /// The body was fully read to a clean EOF.
    Complete,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Failed => "failed",
            Outcome::Incomplete => "incomplete",
            Outcome::Complete => "complete",
        })
    }
}

/// The authorized URL category associated with a request.
///
/// Only the scheme and the authority (host and port) are retained -- never the
/// path, query or fragment.
#[derive(Clone)]
pub struct Endpoint {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Endpoint {
    fn from_url(url: &Url) -> Endpoint {
        Endpoint {
            scheme: url.scheme().to_owned(),
            host: url.host_str().unwrap_or("").to_owned(),
            port: url.port(),
        }
    }

    /// The URL scheme (`http`, `https`, ...).
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The URL host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The explicit port in the URL, if any.
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the authorized category is ever rendered.
        write!(f, "{}://{}", self.scheme, self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// The error captured by a failed receipt, preserving the original cause and
/// HTTP status.
///
/// The originating [`crate::Error`] is available through
/// [`ReceiptError::cause`] and [`std::error::Error::source`]. The URL has been
/// stripped from that error; only the [`Endpoint`] category is reported.
#[derive(Debug, Clone)]
pub struct ReceiptError {
    phase: Phase,
    status: Option<StatusCode>,
    cause: Arc<crate::Error>,
}

impl ReceiptError {
    /// The phase during which the error occurred.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The response status code, if the error carried one.
    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }

    /// The original error returned by the client.
    ///
    /// Its URL has been stripped; only the [`Endpoint`] on the receipt
    /// identifies the target category.
    pub fn cause(&self) -> &crate::Error {
        &self.cause
    }
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request failed during {}: {}", self.phase, self.cause)?;
        if let Some(status) = self.status {
            write!(f, " (status {status})")?;
        }
        Ok(())
    }
}

impl StdError for ReceiptError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.cause)
    }
}

/// A snapshot of a request's [`Receipt`].
///
/// Obtained with [`Receipt::snapshot`], for example after consuming or
/// dropping the tracked response.
#[derive(Debug, Clone)]
pub struct RequestReceipt {
    /// How far the request got.
    pub phase: Phase,
    /// The terminal outcome.
    pub outcome: Outcome,
    /// Number of body bytes actually delivered to the caller.
    pub bytes_delivered: u64,
    /// The authorized URL category; no path, query or header values.
    pub endpoint: Endpoint,
    /// Present iff `outcome == `[`Outcome::Failed`].
    pub error: Option<ReceiptError>,
}

impl RequestReceipt {
    /// Returns `true` if the body was read to a complete, clean EOF.
    pub fn is_complete(&self) -> bool {
        self.outcome == Outcome::Complete
    }

    /// Returns `true` if the response was dropped before the body finished.
    pub fn is_incomplete(&self) -> bool {
        self.outcome == Outcome::Incomplete
    }

    /// Returns `true` if the request failed.
    pub fn is_failed(&self) -> bool {
        self.outcome == Outcome::Failed
    }
}

impl fmt::Display for RequestReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt: {} at phase {}, {} body bytes delivered to {:?}",
            self.outcome, self.phase, self.bytes_delivered, self.endpoint
        )?;
        if let Some(ref err) = self.error {
            write!(f, ": {err}")?;
        }
        Ok(())
    }
}

/// Shared, finalized-once state behind a [`Receipt`] and the tracked body.
struct State {
    phase: AtomicU8,
    bytes: AtomicU64,
    finalized: AtomicBool,
    endpoint: Endpoint,
    error: Mutex<Option<ReceiptError>>,
}

/// A live, clonable receipt handle for an in-flight request.
///
/// The receipt is finalized exactly once, when the body completes, errors, or
/// the response is dropped. [`Receipt::snapshot`] can be called at any time.
#[derive(Clone)]
pub struct Receipt {
    state: Arc<State>,
}

impl fmt::Debug for Receipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.snapshot(), f)
    }
}

impl Receipt {
    fn new(endpoint: Endpoint) -> Receipt {
        Receipt {
            state: Arc::new(State {
                phase: AtomicU8::new(PHASE_BUILD),
                bytes: AtomicU64::new(0),
                finalized: AtomicBool::new(false),
                endpoint,
                error: Mutex::new(None),
            }),
        }
    }

    /// Snapshot the current state of the receipt.
    pub fn snapshot(&self) -> RequestReceipt {
        let phase = Phase::from_u8(self.state.phase.load(Ordering::Acquire));
        let bytes_delivered = self.state.bytes.load(Ordering::Acquire);
        let finalized = self.state.finalized.load(Ordering::Acquire);
        let error = self.state.error.lock().unwrap().clone();

        let outcome = if error.is_some() {
            Outcome::Failed
        } else if finalized {
            // The terminal phase distinguishes a clean EOF from an early drop.
            if phase == Phase::Complete {
                Outcome::Complete
            } else {
                Outcome::Incomplete
            }
        } else {
            // Still in flight: there is no terminal outcome yet.
            Outcome::Incomplete
        };

        RequestReceipt {
            phase,
            outcome,
            bytes_delivered,
            endpoint: self.state.endpoint.clone(),
            error,
        }
    }

    /// Finalize once. Returns true if this call performed the finalization.
    fn finalize(&self) -> bool {
        self.state
            .finalized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn enter_await_headers(&self) {
        self.state
            .phase
            .store(PHASE_AWAIT_HEADERS, Ordering::Release);
    }

    fn headers_received(&self) {
        self.state
            .phase
            .store(PHASE_CONSUME_BODY, Ordering::Release);
    }

    fn record_failure(&self, phase: Phase, err: Error) {
        if !self.finalize() {
            return;
        }
        self.state.phase.store(phase.as_u8(), Ordering::Release);
        let status = err.status();
        // Strip the URL: only the authorized Endpoint category is retained.
        let cause = Arc::new(err.without_url());
        *self.state.error.lock().unwrap() = Some(ReceiptError {
            phase,
            status,
            cause,
        });
    }

    fn record_body_error(&self, shared: Arc<crate::Error>) {
        if !self.finalize() {
            return;
        }
        self.state
            .phase
            .store(PHASE_CONSUME_BODY, Ordering::Release);
        let status = shared.status();
        *self.state.error.lock().unwrap() = Some(ReceiptError {
            phase: Phase::ConsumeBody,
            status,
            cause: shared,
        });
    }

    fn record_complete(&self) {
        if !self.finalize() {
            return;
        }
        self.state.phase.store(PHASE_COMPLETE, Ordering::Release);
    }

    fn add_bytes(&self, n: u64) {
        if n != 0 {
            self.state.bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Mark an early drop: the body was abandoned without an observed error
    /// or EOF. Leaves any existing failure/completion untouched.
    fn mark_dropped(&self) {
        if self.finalize() {
            // Headers had arrived, so an unfinished body is always at the
            // consume-body stage.
            self.state
                .phase
                .store(PHASE_CONSUME_BODY, Ordering::Release);
        }
    }
}

/// The error type yielded by the tracked body. Wraps the original transport
/// error while being shareable between the yielded error and the receipt.
#[derive(Debug, Clone)]
pub(crate) struct SharedBodyError(Arc<crate::Error>);

impl fmt::Display for SharedBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl StdError for SharedBodyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.0)
    }
}

pin_project! {
    /// Response body wrapper that reports delivered bytes, errors, EOF and
    /// early drops to a [`Receipt`].
    pub(crate) struct TrackedBody {
        #[pin]
        inner: ResponseBody,
        receipt: Receipt,
    }

    impl PinnedDrop for TrackedBody {
        fn drop(this: Pin<&mut Self>) {
            // Dropping before a clean EOF or an observed error is
            // "incomplete", never "failed": no error occurred, the body was
            // just not finished.
            this.receipt.mark_dropped();
        }
    }
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = SharedBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.receipt.add_bytes(data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                // The headers had already been delivered, so whatever the
                // transport reports is a *body* failure (e.g. a connection
                // reset or a body shorter than Content-Length). Preserve the
                // original error as the cause; do not guess a DNS/TLS stage.
                let wrapped = Arc::new(crate::error::body(err).without_url());
                this.receipt.record_body_error(wrapped.clone());
                Poll::Ready(Some(Err(SharedBodyError(wrapped))))
            }
            Poll::Ready(None) => {
                this.receipt.record_complete();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

/// The result of [`RequestBuilder::send_with_receipt`].
///
/// If the response headers arrived, [`ReceiptedResponse::response`] is
/// `Some`. That response is not yet finished: consume its body (or drop it)
/// to finalize the receipt.
#[derive(Debug)]
pub struct ReceiptedResponse {
    /// The response, if the headers were received.
    pub response: Option<Response>,
    /// The live receipt handle.
    pub receipt: Receipt,
}

impl ReceiptedResponse {
    /// Drop the response (if still present) and snapshot the finalized
    /// receipt. Dropping an unread response is recorded as
    /// [`Outcome::Incomplete`].
    pub fn into_receipt(mut self) -> RequestReceipt {
        drop(self.response.take());
        self.receipt.snapshot()
    }
}

pin_project! {
    /// Future driving a receipt-tracked send.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    struct ReceiptedSend {
        receipt: Receipt,
        #[pin]
        inner: Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>>,
        entered: bool,
    }
}

impl Future for ReceiptedSend {
    type Output = ReceiptedResponse;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<ReceiptedResponse> {
        let mut this = self.project();
        if !*this.entered {
            *this.entered = true;
            this.receipt.enter_await_headers();
        }
        match this.inner.as_mut().poll(cx) {
            Poll::Ready(Ok(response)) => {
                this.receipt.headers_received();
                let (parts, body, url) = response.into_parts_url();
                let tracked = TrackedBody {
                    inner: body,
                    receipt: this.receipt.clone(),
                };
                let response = Response::from_tracked_parts(parts, tracked, url);
                Poll::Ready(ReceiptedResponse {
                    response: Some(response),
                    receipt: this.receipt.clone(),
                })
            }
            Poll::Ready(Err(err)) => {
                // A failure here never happened while consuming the body: the
                // headers never arrived. Connection refused, DNS failure and
                // TLS handshake failure all stay at AwaitHeaders.
                let phase = if err.is_builder() {
                    Phase::Build
                } else {
                    Phase::AwaitHeaders
                };
                this.receipt.record_failure(phase, err);
                Poll::Ready(ReceiptedResponse {
                    response: None,
                    receipt: this.receipt.clone(),
                })
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl fmt::Debug for ReceiptedSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptedSend").finish_non_exhaustive()
    }
}

impl RequestBuilder {
    /// Sends the request with an explicit receipt.
    ///
    /// Unlike [`RequestBuilder::send`], this always resolves to a
    /// [`ReceiptedResponse`] rather than returning an error. Build and
    /// pre-header failures (including connection failures such as a refused
    /// port, DNS failure or a TLS handshake failure) are captured in the
    /// receipt's [`Outcome::Failed`] at [`Phase::Build`] or
    /// [`Phase::AwaitHeaders`] respectively -- they are never misreported as
    /// body errors.
    ///
    /// A returned response only means the headers arrived. The body must be
    /// consumed to reach [`Outcome::Complete`]; dropping the response early
    /// records [`Outcome::Incomplete`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn run() {
    /// let client = reqwest::Client::new();
    /// let tracked = client
    ///     .get("http://example.com/")
    ///     .send_with_receipt()
    ///     .await;
    ///
    /// if let Some(response) = tracked.response {
    ///     // Getting the response did not finish the body.
    ///     match response.bytes().await {
    ///         Ok(_bytes) => {
    ///             let receipt = tracked.receipt.snapshot();
    ///             assert!(receipt.is_complete());
    ///         }
    ///         Err(_err) => {
    ///             let receipt = tracked.receipt.snapshot();
    ///             assert!(receipt.is_failed());
    ///             assert_eq!(receipt.phase, reqwest::receipt::Phase::ConsumeBody);
    ///         }
    ///     }
    /// } else {
    ///     // Headers never arrived: a build or await-headers failure.
    ///     let receipt = tracked.receipt.snapshot();
    ///     assert!(receipt.is_failed());
    /// }
    /// # }
    /// ```
    pub fn send_with_receipt(self) -> impl Future<Output = ReceiptedResponse> + Send {
        let endpoint = Endpoint::from_url(self.receipt_url());
        let receipt = Receipt::new(endpoint);

        let (client, built) = self.build_split();
        let fut: Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>> = match built {
            Ok(request) => Box::pin(client.execute(request)),
            Err(err) => Box::pin(std::future::ready(Err(err))),
        };

        ReceiptedSend {
            receipt,
            inner: fut,
            entered: false,
        }
    }
}
