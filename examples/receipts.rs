//! Explicit request receipts example.
//!
//! It spins up a tiny raw loopback server (no external network, no Docker)
//! that serves three different responses and also demonstrates a connection
//! failure:
//!
//! It spins up a tiny raw loopback server (no external network, no Docker)
//! that serves three different responses and also demonstrates a connection
//! failure:
//!
//! - `/ok`: headers and a complete body that reaches EOF.
//! - `/short`: headers succeed, but the body is shorter than the declared
//!   `Content-Length`, so the receipt is a body failure.
//! - `/drop`: headers succeed but the response is dropped unread, so the
//!   receipt is incomplete (not complete and not failed).
//! - refused: nothing is listening; the failure stays at awaiting headers
//!   and is never misreported as a body error.
//!
//! Local (scoped) commands to build/run just this example:
//!
//! ```sh
//! cargo run --example receipts --features receipts
//! cargo build --example receipts --features receipts
//! cargo test --test receipts --features receipts
//! ```

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_request(sock: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
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
    buf
}

async fn loopback_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Serve three sequential requests, one per path.
        for _ in 0..3 {
            let (mut sock, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };

            let request = read_request(&mut sock).await;
            let head = String::from_utf8_lossy(&request);

            let response: Vec<u8> = if head.starts_with("GET /short") {
                // Claim 64 bytes but deliver only 5, then close.
                b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nshort".to_vec()
            } else if head.starts_with("GET /drop") {
                let body = "this body is never read by the client";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .into_bytes()
            } else {
                let body = "the complete body";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .into_bytes()
            };

            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
            // Closing the socket at the end of the task signals EOF / reset.
        }
    });

    addr
}

#[tokio::main]
async fn main() {
    let addr = loopback_server().await;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // 1. Complete: read the whole body to EOF.
    {
        let tracked = client
            .get(format!("http://{addr}/ok?secret=not-recorded"))
            .send_with_receipt()
            .await;
        let response = tracked.response.expect("headers arrive");
        let body = response.text().await.unwrap();
        println!("1) body = {body:?}");
        println!("   {}", tracked.receipt.snapshot());
    }

    // 2. Body failure: headers OK, body shorter than Content-Length.
    {
        let tracked = client
            .get(format!("http://{addr}/short"))
            .send_with_receipt()
            .await;
        let response = tracked.response.expect("headers arrive");
        match response.bytes().await {
            Ok(bytes) => println!("2) unexpected body: {bytes:?}"),
            Err(err) => println!("2) body error: {err}"),
        }
        println!("   {}", tracked.receipt.snapshot());
    }

    // 3. Incomplete: headers OK, body dropped before being read.
    {
        let tracked = client
            .get(format!("http://{addr}/drop"))
            .send_with_receipt()
            .await;
        let response = tracked.response.expect("headers arrive");
        drop(response); // unread -> incomplete, not failed
        println!("3) {}", tracked.receipt.snapshot());
    }

    // 4. Connection failure: nothing listening. Reported at await-headers.
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);

        let tracked = client
            .get(format!("http://{dead}/"))
            .send_with_receipt()
            .await;
        assert!(tracked.response.is_none());
        println!("4) {}", tracked.receipt.snapshot());
    }
}
