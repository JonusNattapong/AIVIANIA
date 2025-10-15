//! Middleware module - Support for before/after request processing.
//!
//! This module provides middleware traits and stacks for processing requests and responses.

use crate::database::Repository;
use hyper::{Body, Request, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Type alias for middleware results
pub type MiddlewareResult<T> = Result<T, Response<Body>>;

/// Trait for middleware.
pub trait Middleware: Send + Sync {
    /// Process before the request is handled.
    /// Return Ok(req) to continue, or Err(response) to short-circuit.
    fn before(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        Box::pin(async move { Ok(req) })
    }

    /// Process after the response is generated.
    fn after(
        &self,
        resp: Response<Body>,
    ) -> Pin<Box<dyn Future<Output = Response<Body>> + Send + '_>> {
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
    fn before(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send>> {
        Box::pin(async move {
            println!("Request: {} {}", req.method(), req.uri());
            Ok(req)
        })
    }
}

// Role-based access control middleware
pub struct RoleMiddleware {
    required_role: String,
    user_repo: Arc<crate::database::repositories::UserRepository<crate::database::DatabaseManager>>,
    rbac_service: Arc<crate::auth::rbac::RBACService>,
}

impl RoleMiddleware {
    pub fn new(
        required_role: &str,
        user_repo: Arc<
            crate::database::repositories::UserRepository<crate::database::DatabaseManager>,
        >,
        rbac_service: Arc<crate::auth::rbac::RBACService>,
    ) -> Self {
        Self {
            required_role: required_role.to_string(),
            user_repo,
            rbac_service,
        }
    }
}

impl Middleware for RoleMiddleware {
    fn before(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        let required_role = self.required_role.clone();
        let user_repo = self.user_repo.clone();
        let rbac_service = self.rbac_service.clone();
        Box::pin(async move {
            // Read Claims from request extensions (set by AuthMiddleware)
            if let Some(claims) = req.extensions().get::<crate::auth::Claims>() {
                if let Ok(user_id) = claims.sub.parse::<i64>() {
                    if let Ok(Some(user)) = user_repo.find_by_id(user_id).await {
                        let auth_user = user.to_auth_user();
                        let has = rbac_service.has_role(
                            &auth_user,
                            &crate::auth::models::Role::Custom(required_role.clone()),
                        );
                        if has {
                            return Ok(req);
                        }
                    }
                }
                return Err(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Forbidden: insufficient role"))
                    .unwrap());
            }

            // No Claims in extensions (user not authenticated)
            Err(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized"))
                .unwrap())
        })
    }
}

// Duplicate simple RoleMiddleware removed; RBAC-capable RoleMiddleware above is used instead.

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Method, Request, StatusCode};

    // Mock middleware that adds a header in before
    struct MockBeforeMiddleware;
    impl Middleware for MockBeforeMiddleware {
        fn before(
            &self,
            mut req: Request<Body>,
        ) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send>> {
            Box::pin(async move {
                req.headers_mut()
                    .insert("x-mock", "before".parse().unwrap());
                Ok(req)
            })
        }
    }

    // Mock middleware that adds a header in after
    struct MockAfterMiddleware;
    impl Middleware for MockAfterMiddleware {
        fn after(
            &self,
            mut resp: Response<Body>,
        ) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> {
            Box::pin(async move {
                resp.headers_mut()
                    .insert("x-mock", "after".parse().unwrap());
                resp
            })
        }
    }

    // Mock middleware that short-circuits
    struct MockShortCircuitMiddleware;
    impl Middleware for MockShortCircuitMiddleware {
        fn before(
            &self,
            _req: Request<Body>,
        ) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send>> {
            Box::pin(async move {
                Err(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Short-circuited"))
                    .unwrap())
            })
        }
    }

    #[tokio::test]
    async fn test_middleware_stack_new() {
        let stack = MiddlewareStack::new();
        assert!(stack.middlewares.is_empty());
    }

    #[tokio::test]
    async fn test_middleware_stack_add() {
        let mut stack = MiddlewareStack::new();
        stack.add(Box::new(LoggingMiddleware));
        assert_eq!(stack.middlewares.len(), 1);
    }

    #[tokio::test]
    async fn test_middleware_stack_before_success() {
        let mut stack = MiddlewareStack::new();
        stack.add(Box::new(MockBeforeMiddleware));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let result = stack.before(req).await;
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.headers().get("x-mock").unwrap(), "before");
    }

    #[tokio::test]
    async fn test_middleware_stack_before_short_circuit() {
        let mut stack = MiddlewareStack::new();
        stack.add(Box::new(MockShortCircuitMiddleware));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let result = stack.before(req).await;
        assert!(result.is_err());
        let resp = result.unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_middleware_stack_after() {
        let mut stack = MiddlewareStack::new();
        stack.add(Box::new(MockAfterMiddleware));

        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();

        let result = stack.after(resp).await;
        assert_eq!(result.headers().get("x-mock").unwrap(), "after");
    }

    #[tokio::test]
    async fn test_logging_middleware() {
        let middleware = LoggingMiddleware;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let result = middleware.before(req).await;
        assert!(result.is_ok());
        // Logging is just println, hard to test output, but ensures no panic
    }
}
