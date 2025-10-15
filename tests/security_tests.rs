use aiviania::security::{CsrfProtection, CsrfTokenGenerator};
use aiviania::security::cors::CorsConfig;
use aiviania::security::headers::{SecurityHeadersConfig, SecurityHeadersProcessor};
use aiviania::security::SecurityMiddleware;
use aiviania::security::CorsMiddleware;
use aiviania::security::SecurityEventLogger;
use hyper::{Body, Request, Method, Response};
use std::sync::Arc;

#[tokio::test]
async fn csrf_generate_and_validate_via_process() {
    let protection = Arc::new(CsrfProtection::new(3600));
    let generator = CsrfTokenGenerator::new(protection.clone());
    let token = generator.generate_token().await;

    // Build a POST request with header and cookie
    let req = Request::builder()
        .method(Method::POST)
        .uri("/submit")
        .header("cookie", format!("csrf_token={}", token))
        .header("X-CSRF-Token", token.clone())
        .body(Body::empty())
        .unwrap();

    let logger = Arc::new(SecurityEventLogger::new(10));
    let result = protection.process(req, logger).await;
    assert!(result.is_ok(), "CSRF token should validate via middleware process");
}

#[tokio::test]
async fn csrf_missing_token_fails() {
    let protection = Arc::new(CsrfProtection::new(3600));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/submit")
        .body(Body::empty())
        .unwrap();

    let logger = Arc::new(SecurityEventLogger::new(10));
    let result = protection.process(req, logger).await;
    assert!(result.is_err(), "Missing CSRF token should cause validation error");
}

#[tokio::test]
async fn cors_rejects_disallowed_origin() {
    let mut config = CorsConfig::default();
    config.allowed_origins = vec!["https://allowed.example".to_string()];
    let cors = CorsMiddleware::with_config(config);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .unwrap();

    let logger = Arc::new(SecurityEventLogger::new(10));
    let res = cors.process(req, logger).await;
    assert!(res.is_err(), "CORS should reject disallowed origin");
}

#[tokio::test]
async fn security_headers_processor_adds_headers() {
    let config = SecurityHeadersConfig::default();
    let processor = SecurityHeadersProcessor::new(config);

    let resp = Response::builder().status(200).body(Body::from("ok")).unwrap();

    let processed = processor.process_response(resp);
    // Expect at least one of the default security headers to be present
    assert!(processed.headers().contains_key("X-Frame-Options") || processed.headers().contains_key("Content-Security-Policy"));
}
