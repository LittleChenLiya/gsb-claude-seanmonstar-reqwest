//! Tests for the opt-in `receipts` feature.
//!
//! These use a tiny raw loopback TCP fixture so that the server has complete
//! control over the bytes on the wire (notably, declaring a `Content-Length`
//! and then closing the connection early). No Docker, no external network.
#![cfg(not(target_arch = "wasm32"))]

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::receipt::{Outcome, Phase};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Bind a loopback listener and spawn one connection handler that sends the
/// raw `response` bytes after reading the request headers.
async fn raw_server<F>(mut handle: F) -> SocketAddr
where
    F: FnMut(TcpStream, Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            // Read just the request headers.
            loop {
                let n = sock.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            handle(sock, buf).await;
        }
    });
    addr
}

/// Read a request then write a fixed response and leave the connection open
/// briefly so the client can observe a clean EOF only when *we* finish.
async fn serve_once(response: &'static [u8]) -> SocketAddr {
    raw_server(move |mut sock, _req| {
        Box::pin(async move {
            sock.write_all(response).await.unwrap();
            sock.flush().await.unwrap();
        })
    })
    .await
}

fn ok_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

#[tokio::test]
async fn full_eof_is_complete() {
    let body = "hello receipts";
    let response = ok_response(body);
    let addr = serve_once(response.leak()).await;

    let client = Client::builder()
        .pool_idle_timeout(Duration::from_millis(50))
        .build()
        .unwrap();

    let tracked = client
        .get(format!("http://{addr}/secret-path?token=shh"))
        .send_with_receipt()
        .await;

    let response = tracked.response.expect("headers should arrive");
    assert_eq!(response.status(), 200);
    let bytes = response.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), body.as_bytes());

    // `bytes` consumed the body to a clean EOF, which finalizes the receipt.
    let receipt = tracked.receipt.snapshot();
    assert!(receipt.is_complete());
    assert_eq!(receipt.outcome, Outcome::Complete);
    assert_eq!(receipt.phase, Phase::Complete);
    assert_eq!(receipt.bytes_delivered, body.len() as u64);
    assert!(receipt.error.is_none());

    // Only the authorized category is retained, never path/query.
    let rendered = format!("{:?}", receipt.endpoint);
    assert!(rendered.starts_with("http://127.0.0.1"));
    let full = receipt.to_string();
    assert!(!full.contains("secret-path"));
    assert!(!full.contains("token"));
    assert!(!full.contains("shh"));
}

#[tokio::test]
async fn headers_ok_but_body_shorter_than_length_is_body_failure() {
    // Declare 64 bytes but only deliver 5, then close the connection.
    let response: &'static [u8] = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{}",
            "short"
        )
        .into_bytes()
        .into_boxed_slice(),
    );
    let addr = serve_once(response).await;

    let client = Client::builder().build().unwrap();
    let tracked = client
        .get(format!("http://{addr}/"))
        .send_with_receipt()
        .await;

    let response = tracked.response.expect("headers should arrive");
    assert_eq!(response.status(), 200);

    let err = response.bytes().await.expect_err("body must fail");
    // The returned error is a reqwest body/decode error preserving the cause.
    assert!(err.is_body() || err.is_decode(), "err = {err:?}");

    // `bytes` moved the response; the body error already finalized the
    // receipt.
    let receipt = tracked.receipt.snapshot();
    assert!(receipt.is_failed());
    assert_eq!(receipt.outcome, Outcome::Failed);
    assert_eq!(receipt.phase, Phase::ConsumeBody);
    assert_eq!(receipt.bytes_delivered, 5);

    let receipt_err = receipt.error.as_ref().expect("error recorded");
    assert_eq!(receipt_err.phase(), Phase::ConsumeBody);
    // The original cause is preserved.
    let _source = receipt_err
        .source_chain_first()
        .expect("cause chain retained");
}

#[tokio::test]
async fn dropped_before_read_is_incomplete() {
    let body = "never read";
    let response = ok_response(body);
    let addr = serve_once(response.leak()).await;

    let client = Client::builder().build().unwrap();
    let tracked = client
        .get(format!("http://{addr}/"))
        .send_with_receipt()
        .await;

    let response = tracked.response.expect("headers should arrive");
    assert_eq!(response.status(), 200);
    // Drop without reading anything.
    drop(response);

    let receipt = tracked.receipt.snapshot();
    assert!(receipt.is_incomplete());
    assert_eq!(receipt.outcome, Outcome::Incomplete);
    assert_eq!(receipt.phase, Phase::ConsumeBody);
    assert_eq!(receipt.bytes_delivered, 0);
    assert!(receipt.error.is_none());
}

#[tokio::test]
async fn partially_read_then_dropped_is_incomplete_with_bytes() {
    let body = "0123456789ABCDEF";
    let response = ok_response(body);
    let addr = serve_once(response.leak()).await;

    let client = Client::builder().build().unwrap();
    let tracked = client
        .get(format!("http://{addr}/"))
        .send_with_receipt()
        .await;

    let mut response = tracked.response.expect("headers should arrive");
    let chunk = response.chunk().await.unwrap().unwrap();
    assert!(!chunk.is_empty());

    // Drop midway: incomplete, but delivered bytes are recorded.
    drop(response);
    let receipt = tracked.receipt.snapshot();
    assert_eq!(receipt.outcome, Outcome::Incomplete);
    assert_eq!(receipt.phase, Phase::ConsumeBody);
    assert!(receipt.bytes_delivered > 0);
    assert!(receipt.error.is_none());
}

#[tokio::test]
async fn connection_refused_is_await_headers_not_body() {
    // Grab a port then drop the listener so nothing is listening.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let tracked = client
        .get(format!("http://{addr}/"))
        .send_with_receipt()
        .await;

    assert!(tracked.response.is_none(), "no response headers possible");
    let receipt = tracked.receipt.snapshot();
    assert!(receipt.is_failed());
    assert_eq!(receipt.outcome, Outcome::Failed);
    assert_eq!(receipt.phase, Phase::AwaitHeaders);
    assert_eq!(receipt.bytes_delivered, 0);

    let err = receipt.error.as_ref().expect("error recorded");
    assert_eq!(err.phase(), Phase::AwaitHeaders);
    // The original error/cause is preserved and is a connection-level error.
    assert!(
        err.cause().is_connect() || err.cause().is_request(),
        "cause = {:?}",
        err.cause()
    );
}

#[tokio::test]
async fn bad_url_is_build_failure() {
    let client = Client::builder().build().unwrap();
    // Not a valid http/https URL: builder error, before sending anything.
    let tracked = client.get("not-a-url-at-all").send_with_receipt().await;

    assert!(tracked.response.is_none());
    let receipt = tracked.receipt.snapshot();
    assert!(receipt.is_failed());
    assert_eq!(receipt.outcome, Outcome::Failed);
    assert_eq!(receipt.phase, Phase::Build);
    assert_eq!(receipt.bytes_delivered, 0);

    let err = receipt.error.as_ref().expect("error recorded");
    assert_eq!(err.phase(), Phase::Build);
    assert!(err.cause().is_builder());
}

#[tokio::test]
async fn into_receipt_drops_unread_as_incomplete() {
    let body = "via into_receipt";
    let response = ok_response(body);
    let addr = serve_once(response.leak()).await;

    let client = Client::builder().build().unwrap();
    let tracked = client
        .get(format!("http://{addr}/"))
        .send_with_receipt()
        .await;
    assert!(tracked.response.is_some());

    // Dropping the response via into_receipt without reading -> incomplete.
    let receipt = tracked.into_receipt();
    assert_eq!(receipt.outcome, Outcome::Incomplete);
    assert_eq!(receipt.phase, Phase::ConsumeBody);
}

#[tokio::test]
async fn status_error_keeps_status_and_body_still_complete() {
    // A 503 with a complete body: headers arrive fine; the receipt itself is
    // complete because the body EOFs cleanly (a bad status is not a body
    // failure).
    let response: &'static [u8] = Box::leak(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope"
            .to_vec()
            .into_boxed_slice(),
    );
    let addr = serve_once(response).await;

    let client = Client::builder().build().unwrap();
    let tracked = client
        .get(format!("http://{addr}/"))
        .send_with_receipt()
        .await;
    let response = tracked.response.unwrap();
    assert_eq!(response.status(), 503);

    // Consume the full body first: a clean EOF completes the receipt even
    // though the status would be considered an error by the caller.
    let bytes = response.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), b"nope".as_slice());

    let receipt = tracked.receipt.snapshot();
    assert!(receipt.is_complete());
    assert_eq!(receipt.outcome, Outcome::Complete);
    assert_eq!(receipt.phase, Phase::Complete);
    assert_eq!(receipt.bytes_delivered, 4);
    assert!(receipt.error.is_none());
}

// Small local extension to read the first source of a receipt error, keeping
// the test independent of private fields.
trait SourceChain {
    fn source_chain_first(&self) -> Option<&(dyn std::error::Error + 'static)>;
}

impl SourceChain for reqwest::receipt::ReceiptError {
    fn source_chain_first(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use std::error::Error;
        self.source()
    }
}
