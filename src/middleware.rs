//! Middleware module - Support for before/after request processing.
//!
//! This module provides middleware traits and stacks for processing requests and responses.

use std::future::Future;
use std::pin::Pin;
use hyper::{Request, Response, Body, StatusCode};
use std::sync::Arc;
use crate::auth::AuthService;
use crate::database::Database;

/// Trait for middleware.
pub trait Middleware: Send + Sync {
    /// Process before the request is handled.
    /// Return Ok(req) to continue, or Err(response) to short-circuit.
    fn before(&self, req: Request<Body>) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        Box::pin(async move { Ok(req) })
    }

    /// Process after the response is generated.
    fn after(&self, resp: Response<Body>) -> Pin<Box<dyn Future<Output = Response<Body>> + Send + '_>> {
        Box::pin(async move { resp })
    }
}

/// Stack of middleware.
pub struct MiddlewareStack {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl MiddlewareStack {
    /// Create a new middleware stack.
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    /// Add middleware to the stack.
    pub fn add(&mut self, middleware: Box<dyn Middleware>) {
        self.middlewares.push(middleware);
    }

    /// Apply before middleware.
    pub async fn before(&self, mut req: Request<Body>) -> Result<Request<Body>, Response<Body>> {
        for middleware in &self.middlewares {
            match middleware.before(req).await {
                Ok(r) => req = r,
                Err(resp) => return Err(resp),
            }
        }
        Ok(req)
    }

    /// Apply after middleware.
    pub async fn after(&self, mut resp: Response<Body>) -> Response<Body> {
        for middleware in &self.middlewares {
            resp = middleware.after(resp).await;
        }
        resp
    }
}

// Example middleware: Logging
pub struct LoggingMiddleware;

impl Middleware for LoggingMiddleware {
    fn before(&self, req: Request<Body>) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send>> {
        Box::pin(async move {
            println!("Request: {} {}", req.method(), req.uri());
            Ok(req)
        })
    }
}

// Role-based access control middleware
pub struct RoleMiddleware {
    required_role: String,
    db: Arc<Database>,
}

impl RoleMiddleware {
    pub fn new(required_role: &str, db: Arc<Database>) -> Self {
        Self {
            required_role: required_role.to_string(),
            db,
        }
    }
}

impl Middleware for RoleMiddleware {
    fn before(&self, req: Request<Body>) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        let required_role = self.required_role.clone();
        let db = self.db.clone();
        Box::pin(async move {
            // Read Claims from request extensions (set by AuthMiddleware)
            if let Some(claims) = req.extensions().get::<crate::auth::Claims>() {
                if let Ok(Some(user)) = db.get_user(&claims.sub).await {
                    if let Ok(has) = db.user_has_role(user.id, &required_role).await {
                        if has {
                            return Ok(req);
                        }
                    }
                }
                return Err(Response::builder().status(StatusCode::FORBIDDEN).body(Body::from("Forbidden: insufficient role")).unwrap());
            }

            // No Claims in extensions (user not authenticated)
            Err(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("Unauthorized")).unwrap())
        })
    }
}

// Duplicate simple RoleMiddleware removed; RBAC-capable RoleMiddleware above is used instead.