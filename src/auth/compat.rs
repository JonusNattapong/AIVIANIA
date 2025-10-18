use crate::response::AivianiaResponse;
use hyper::{Body, Request, StatusCode};
use crate::plugin::PluginManager;
use std::sync::Arc;

// Minimal compatibility stubs for login/register handlers used by examples.
// These simply return 501 Not Implemented so examples compile and can be
// migrated later to full implementations.

pub async fn login_handler(_req: Request<Body>, _plugins: Arc<PluginManager>) -> AivianiaResponse {
    AivianiaResponse::new(StatusCode::NOT_IMPLEMENTED).body(Body::from("login handler not implemented in compat shim"))
}

pub async fn register_handler(_req: Request<Body>, _plugins: Arc<PluginManager>) -> AivianiaResponse {
    AivianiaResponse::new(StatusCode::NOT_IMPLEMENTED).body(Body::from("register handler not implemented in compat shim"))
}
