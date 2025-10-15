use crate::body_buffer::buffer_request_body;
use hyper::{Request, Body, Response};
use std::sync::Arc;
use async_trait::async_trait;

pub struct BodyBufferMiddleware {
    pub max_bytes: usize,
}

impl BodyBufferMiddleware {
    pub fn new(max_bytes: usize) -> Self { Self { max_bytes } }
}

#[async_trait]
pub trait SimpleMiddleware: Send + Sync + 'static {
    async fn handle(&self, req: Request<Body>, next: Arc<dyn Fn(Request<Body>) -> futures_util::future::BoxFuture<'static, Response<Body>> + Send + Sync>) -> Response<Body>;
}

#[async_trait]
impl SimpleMiddleware for BodyBufferMiddleware {
    async fn handle(&self, req: Request<Body>, next: Arc<dyn Fn(Request<Body>) -> futures_util::future::BoxFuture<'static, Response<Body>> + Send + Sync>) -> Response<Body> {
        match buffer_request_body(req, self.max_bytes).await {
            Ok((new_req, Some(_bytes))) => next(new_req).await,
            Ok((_req, None)) => {
                // Return 413 Payload Too Large
                Response::builder().status(413).body(Body::from("Payload Too Large")).unwrap()
            }
            Err(_) => Response::builder().status(500).body(Body::from("Internal Error")).unwrap(),
        }
    }
}
