use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task;

use aiviania::observability::middleware::MetricsMiddleware;
use aiviania::security::csrf::CsrfProtection;
use aiviania::security::csrf::CsrfTokenGenerator;
use aiviania::security::cors::CorsMiddleware;
use aiviania::security::headers::SecurityHeadersMiddleware;
use aiviania::{router::Router, router::Route, server::AivianiaServer, response::Response};
use hyper::{Body, Request, StatusCode};

/// Helper that starts a server instance in-process on the given port and returns the
/// bind address string.
async fn start_test_server(port: u16) -> String {
    let mut router = Router::new();

    // Create CSRF and generator
    let csrf = Arc::new(CsrfProtection::new(3600));
    let token_gen = CsrfTokenGenerator::new(Arc::clone(&csrf));

    router.add_route(Route::new(
        "GET",
        "/form",
        move |_req: Request<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| {
            let token_gen = token_gen.clone();
            async move {
                let token = token_gen.generate_token().await;
                let cookie = token_gen.create_token_cookie(&token);
                let header = token_gen.create_token_header(&token);
                let html = format!("<html><body><form method='POST' action='/submit'><input type='hidden' name='csrf_token' value='{}'/><input name='message' /><button type='submit'>Send</button></form></body></html>", token);
                Response::new(StatusCode::OK)
                    .header("set-cookie", cookie.as_str())
                    .header(&header.0, &header.1)
                    .body(Body::from(html))
            }
        },
    ));

    router.add_route(Route::new(
        "POST",
        "/submit",
        |req: Request<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| async move {
            // Middleware handles CSRF; handler simply returns ok
            Response::new(StatusCode::OK).json(&serde_json::json!({"ok": true}))
        },
    ));

    let security_headers = SecurityHeadersMiddleware::new();
    let cors = CorsMiddleware::new(vec!["http://localhost:3000".to_string()]);
    let metrics = MetricsMiddleware::new();

    let server = AivianiaServer::new(router)
        .with_middleware(Box::new(metrics))
        .with_middleware(Box::new(security_headers))
        .with_middleware(Box::new(cors))
        .with_middleware(Box::new(csrf));

    let addr = format!("127.0.0.1:{}", port);

    // Spawn server in background
    let _ = tokio::spawn(async move {
        let _ = server.run(&addr).await;
    });

    // Give server time to bind
    tokio::time::sleep(Duration::from_millis(500)).await;
    addr
}

#[tokio::test]
async fn test_csrf_valid_and_invalid() {
    let addr = start_test_server(4005).await;

    let client = Client::builder().cookie_store(true).build().unwrap();

    // GET /form to receive CSRF token in cookie and header
    let resp = client
        .get(&format!("http://{}/form", addr))
        .send()
        .await
        .expect("GET /form request failed");

    assert!(resp.status().is_success());

    // Extract header token
    let header_token = resp
        .headers()
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Submit with missing token -> expect failure
    let bad = client
        .post(&format!("http://{}/submit", addr))
        .body("message=hello")
        .send()
        .await
        .expect("POST missing token failed");

    assert!(bad.status().is_client_error());

    // Submit with valid header token
    if let Some(token) = header_token {
        let ok = client
            .post(&format!("http://{}/submit", addr))
            .header("X-CSRF-Token", token)
            .body("message=hello")
            .send()
            .await
            .expect("POST with token failed");

        assert!(ok.status().is_success());
    } else {
        panic!("No csrf header token returned from /form");
    }
}

#[tokio::test]
async fn test_cors_preflight_and_metrics() {
    let addr = start_test_server(4006).await;

    // Check CORS preflight
    let client = Client::new();
    let resp = client
        .request(reqwest::Method::OPTIONS, &format!("http://{}/submit", addr))
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .expect("OPTIONS request failed");

    // Should accept preflight and include CORS headers
    assert!(resp.status().is_success());
    assert!(resp.headers().get("access-control-allow-origin").is_some());

    // Check metrics endpoint increments after calling /form
    let client = Client::new();
    let _ = client.get(&format!("http://{}/form", addr)).send().await;
    let metrics = client
        .get(&format!("http://{}/metrics", addr))
        .send()
        .await
        .expect("GET /metrics failed")
        .text()
        .await
        .expect("read metrics body");

    assert!(metrics.contains("http_requests_total") || metrics.contains("aiviania_http_requests_total"));
}
