#![cfg(not(target_arch = "wasm32"))]
#![cfg(not(feature = "rustls-no-provider"))]
mod support;
use support::server;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use reqwest::replay::{Cancellation, Credential, Replay};
use reqwest::{Body, Method, Request, StatusCode, Url};

fn replay_client() -> Replay {
    Replay::new(reqwest::Client::new())
}

fn status_503() -> http::Response<Body> {
    http::Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::default())
        .unwrap()
}

#[tokio::test]
async fn small_get_is_retried_with_credential() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let srv_hits = hits.clone();
    let server = server::http(move |_req| {
        let hits = srv_hits.clone();
        async move {
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                status_503()
            } else {
                http::Response::default()
            }
        }
    });

    let url: Url = format!("http://{}/get", server.addr()).parse().unwrap();
    let credential = Credential::for_request(Method::GET, url.clone());
    let request = Request::new(Method::GET, url);

    let response = replay_client().execute(request, &credential).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn small_byte_body_gets_an_automatic_replay_credential() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let srv_hits = hits.clone();
    let server = server::http(move |req| {
        let hits = srv_hits.clone();
        async move {
            use http_body_util::BodyExt;
            let body = req.collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"replay-me");
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                status_503()
            } else {
                http::Response::default()
            }
        }
    });

    let url: Url = format!("http://{}/upload", server.addr()).parse().unwrap();
    // No explicit body source: the small in-memory body is captured
    // automatically by the wrapper.
    let credential = Credential::for_request(Method::PUT, url.clone());
    let mut request = Request::new(Method::PUT, url);
    *request.body_mut() = Some(Body::from("replay-me"));

    let response = replay_client().execute(request, &credential).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn stream_factory_digest_mismatch_stops_before_sending() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let srv_hits = hits.clone();
    let server = server::http(move |_req| {
        let hits = srv_hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            status_503()
        }
    });

    // The factory produces "one" at first, then changes its content.
    let creations = Arc::new(AtomicUsize::new(0));
    let factory = {
        let creations = creations.clone();
        move || {
            let n = creations.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Some(Body::from("one"))
            } else {
                Some(Body::from("two"))
            }
        }
    };

    let url: Url = format!("http://{}/stream", server.addr()).parse().unwrap();
    let credential = Credential::for_stream(Method::PUT, url.clone(), factory).unwrap();
    let request = Request::new(Method::PUT, url);

    let err = replay_client()
        .execute(request, &credential)
        .await
        .unwrap_err();

    assert!(err.is_body(), "expected a body error, got: {err}");
    // The mismatching rebuild was rejected before sending: only the first
    // attempt reached the server.
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unauthorized_post_is_sent_only_once() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let srv_hits = hits.clone();
    let server = server::http(move |_req| {
        let hits = srv_hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            status_503()
        }
    });

    let url: Url = format!("http://{}/post", server.addr()).parse().unwrap();
    // POST is not idempotent and no explicit authorization was given.
    let credential = Credential::for_request(Method::POST, url.clone());
    let request = Request::new(Method::POST, url);

    let response = replay_client().execute(request, &credential).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn explicitly_authorized_post_is_retried() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let srv_hits = hits.clone();
    let server = server::http(move |_req| {
        let hits = srv_hits.clone();
        async move {
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                status_503()
            } else {
                http::Response::default()
            }
        }
    });

    let url: Url = format!("http://{}/post", server.addr()).parse().unwrap();
    let credential = Credential::for_request(Method::POST, url.clone()).allow_retry();
    let request = Request::new(Method::POST, url);

    let response = replay_client().execute(request, &credential).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn credential_url_is_not_carried_across_redirects() {
    let _ = env_logger::try_init();
    let start_hits = Arc::new(AtomicUsize::new(0));
    let landed_hits = Arc::new(AtomicUsize::new(0));
    let srv_start = start_hits.clone();
    let srv_landed = landed_hits.clone();
    let server = server::http(move |req| {
        let start_hits = srv_start.clone();
        let landed_hits = srv_landed.clone();
        async move {
            match req.uri().path() {
                "/start" => {
                    start_hits.fetch_add(1, Ordering::SeqCst);
                    http::Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", "/landed")
                        .body(Body::default())
                        .unwrap()
                }
                "/landed" => {
                    landed_hits.fetch_add(1, Ordering::SeqCst);
                    status_503()
                }
                other => panic!("unexpected path: {other}"),
            }
        }
    });

    let url: Url = format!("http://{}/start", server.addr()).parse().unwrap();
    let credential = Credential::for_request(Method::GET, url.clone());
    let request = Request::new(Method::GET, url);

    // The default client follows the redirect to /landed, which answers 503.
    // The credential is bound to /start, so the retryable status at the
    // redirected URL must NOT trigger a replay.
    let response = replay_client().execute(request, &credential).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.url().path(), "/landed");
    assert_eq!(start_hits.load(Ordering::SeqCst), 1);
    assert_eq!(landed_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn streaming_body_without_factory_is_not_replayable() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let srv_hits = hits.clone();
    let server = server::http(move |_req| {
        let hits = srv_hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            status_503()
        }
    });

    let url: Url = format!("http://{}/stream", server.addr()).parse().unwrap();
    let credential = Credential::for_request(Method::PUT, url.clone());
    let mut request = Request::new(Method::PUT, url);
    // A true streaming body: not copyable, and no factory was provided.
    let streaming = http_body_util::Full::new(bytes::Bytes::from_static(b"chunk"));
    *request.body_mut() = Some(Body::wrap(streaming));

    let err = replay_client()
        .execute(request, &credential)
        .await
        .unwrap_err();

    assert!(err.is_body(), "expected a body error, got: {err}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_replay_does_not_resend() {
    let _ = env_logger::try_init();
    let hits = Arc::new(AtomicUsize::new(0));
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<()>();
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();
    let seen_tx = Arc::new(Mutex::new(Some(seen_tx)));
    let ack_rx = Arc::new(Mutex::new(Some(ack_rx)));
    let srv_hits = hits.clone();
    let srv_seen = seen_tx.clone();
    let srv_ack = ack_rx.clone();
    let server = server::http(move |_req| {
        let hits = srv_hits.clone();
        let seen_tx = srv_seen.clone();
        let ack_rx = srv_ack.clone();
        async move {
            if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                // Tell the test the first request arrived, then wait until
                // the cancellation has been applied before responding.
                let tx = seen_tx.lock().unwrap().take();
                if let Some(tx) = tx {
                    let _ = tx.send(());
                }
                let rx = ack_rx.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
            }
            status_503()
        }
    });

    let url: Url = format!("http://{}/get", server.addr()).parse().unwrap();
    let credential = Credential::for_request(Method::GET, url.clone());
    let request = Request::new(Method::GET, url);

    let cancel = Cancellation::new();
    let canceller = {
        let cancel = cancel.clone();
        async move {
            seen_rx.await.unwrap();
            cancel.cancel();
            let _ = ack_tx.send(());
        }
    };

    let replay = replay_client();
    let (result, ()) = tokio::join!(
        replay.execute_cancellable(request, &credential, cancel),
        canceller
    );

    let err = result.unwrap_err();
    assert!(err.is_request(), "expected a request error, got: {err:?}");
    assert!(
        format!("{err:?}").contains("cancelled"),
        "expected a cancellation error, got: {err:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
