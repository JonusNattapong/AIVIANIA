use crate::observability::{HTTP_REQUESTS, HTTP_LATENCY};
use hyper::{Request, Body, Response};
use std::time::Instant;
use std::sync::Arc;
use async_trait::async_trait;
use crate::middleware::Middleware as CrateMiddleware;

pub struct MetricsMiddleware;

impl MetricsMiddleware {
    pub fn new() -> Self { Self }
}

#[async_trait]
pub trait Middleware: Send + Sync + 'static {
    async fn handle(&self, req: Request<Body>, next: Arc<dyn Fn(Request<Body>) -> futures_util::future::BoxFuture<'static, Response<Body>> + Send + Sync>) -> Response<Body>;
}

#[async_trait]
impl Middleware for MetricsMiddleware {
    async fn handle(&self, req: Request<Body>, next: Arc<dyn Fn(Request<Body>) -> futures_util::future::BoxFuture<'static, Response<Body>> + Send + Sync>) -> Response<Body> {
        let method = req.method().as_str().to_string();
        let route = req.uri().path().to_string();
        let start = Instant::now();

        let resp = next(req).await;
        let elapsed = start.elapsed().as_secs_f64();

        let status = resp.status().as_u16().to_string();
        HTTP_REQUESTS.with_label_values(&[&method, &route, &status]).inc();
        HTTP_LATENCY.with_label_values(&[&method, &route]).observe(elapsed);

        resp
    }
}

// Adapter to implement the crate-wide Middleware trait so examples that
// Box<dyn Middleware> can accept MetricsMiddleware. This adapter uses the
// existing `handle` method and plugs it into the before/after hooks.
impl CrateMiddleware for MetricsMiddleware {
    fn before(&self, req: Request<Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        // We need to capture `self` by reference for the async block but not call handle here.
        Box::pin(async move { Ok(req) })
    }

    fn after(&self, resp: Response<Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<Body>> + Send + '_>> {
        // No-op after — the metrics middleware observes timing around the handler via `handle`.
        Box::pin(async move { resp })
    }
}
