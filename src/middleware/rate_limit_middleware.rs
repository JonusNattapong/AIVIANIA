use crate::rate_limit::RateLimiter;
use crate::response::AivianiaResponse;
use hyper::{Request, Body, Response};
use std::sync::Arc;

pub struct RateLimitMiddleware {
    limiter: Arc<RateLimiter>,
    key_prefix: String,
}

impl RateLimitMiddleware {
    pub fn new(limiter: Arc<RateLimiter>, key_prefix: &str) -> Self {
        Self { limiter, key_prefix: key_prefix.to_string() }
    }
}

impl crate::middleware::Middleware for RateLimitMiddleware {
    fn before(&self, mut req: Request<Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        let limiter = self.limiter.clone();
        let key = format!("{}:{}", self.key_prefix, req.uri().path());
        Box::pin(async move {
            if limiter.allow(&key).await {
                Ok(req)
            } else {
                let resp = AivianiaResponse::new(hyper::StatusCode::TOO_MANY_REQUESTS).body(Body::from("Too many requests"));
                Err(resp.into())
            }
        })
    }
}
