//! Router module - Handles routing logic.
//!
//! This module provides the Router struct that matches incoming requests to handlers.
//! It supports simple path matching and parameter extraction.

use hyper::{Request, Response, Body, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use crate::plugin::PluginManager;
use crate::response::AivianiaResponse;

/// Represents a route with method, path, handler, and middleware.
pub struct Route {
    method: String,
    path: String,
    handler: Arc<dyn Fn(Request<Body>, Arc<PluginManager>) -> std::pin::Pin<Box<dyn std::future::Future<Output = AivianiaResponse> + Send>> + Send + Sync>,
    middleware: Vec<Box<dyn crate::middleware::Middleware>>,
}

impl Route {
    /// Create a new route.
    pub fn new<F, Fut>(method: &str, path: &str, handler: F) -> Self
    where
        F: Fn(Request<Body>, Arc<PluginManager>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = AivianiaResponse> + Send + 'static,
    {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            handler: Arc::new(move |req, plugins| Box::pin(handler(req, plugins))),
            middleware: Vec::new(),
        }
    }

    /// Add middleware to this route.
    pub fn with_middleware(mut self, middleware: Box<dyn crate::middleware::Middleware>) -> Self {
        self.middleware.push(middleware);
        self
    }
}

/// Router that holds all routes.
pub struct Router {
    routes: HashMap<String, Vec<Route>>,
}

impl Router {
    /// Create a new router.
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Add a route to the router.
    pub fn add_route(&mut self, route: Route) {
        self.routes.entry(route.method.clone()).or_insert_with(Vec::new).push(route);
    }

    /// Handle an incoming request.
    pub async fn handle(&self, mut req: Request<Body>, plugins: Arc<PluginManager>) -> Response<Body> {
        let method = req.method().as_str();
        if let Some(routes) = self.routes.get(method) {
            for route in routes {
                if self.matches(&route.path, req.uri().path()) {
                    // Apply route-specific middleware (short-circuit on Err)
                    for middleware in &route.middleware {
                        match middleware.before(req).await {
                            Ok(r) => req = r,
                            Err(resp) => return resp,
                        }
                    }

                    // Handle the request
                    let mut resp = (route.handler)(req, plugins).await.into();

                    // Apply route-specific middleware in reverse order
                    for middleware in route.middleware.iter().rev() {
                        resp = middleware.after(resp).await;
                    }

                    return resp;
                }
            }
        }
        // 404 Not Found
        AivianiaResponse::new(StatusCode::NOT_FOUND).body(Body::from("Not Found")).into()
    }

    /// Simple path matching (exact match for now; can be extended).
    fn matches(&self, route_path: &str, req_path: &str) -> bool {
        route_path == req_path
    }
}