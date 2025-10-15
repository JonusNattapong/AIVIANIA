use crate::observability::{HTTP_REQUESTS, HTTP_LATENCY};
use hyper::{Request, Body, Response};
use std::time::Instant;
use std::sync::Arc;
use async_trait::async_trait;

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
