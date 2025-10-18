//! Authentication middleware for protecting routes.
//!
//! This module provides middleware for JWT token validation,
//! session-based authentication, and RBAC permission checking.

use crate::auth::jwt::JwtService;
use crate::auth::models::{Permission, User};
use crate::auth::rbac::RBACService;
use crate::auth::session::SessionManager;
use crate::middleware::{Middleware, MiddlewareResult};
use hyper::{header::AUTHORIZATION, HeaderMap, Request, Response, StatusCode};
use std::pin::Pin;
use std::sync::Arc;

/// Authentication middleware for JWT tokens
pub struct AuthMiddleware {
    jwt_service: Arc<JwtService>,
    session_manager: Option<Arc<SessionManager>>,
    #[allow(dead_code)]
    rbac_service: Arc<RBACService>,
}

impl AuthMiddleware {
    /// Create a new authentication middleware with JWT only
    pub fn new(jwt_service: Arc<JwtService>) -> Self {
        Self {
            jwt_service,
            session_manager: None,
            rbac_service: Arc::new(RBACService::new()),
        }
    }

    /// Create a new authentication middleware from an `AuthServiceWrapper` instance.
    /// This is a compatibility helper so examples that construct an `AuthService` (the
    /// backwards-compatible wrapper) can pass it directly.
    pub fn from_auth_service(auth_service: Arc<crate::auth::AuthService>) -> Self {
        AuthMiddleware::new(auth_service.inner())
    }

    /// Create a new authentication middleware with JWT and session support
    pub fn with_session(
        jwt_service: Arc<JwtService>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            jwt_service,
            session_manager: Some(session_manager),
            rbac_service: Arc::new(RBACService::new()),
        }
    }

    /// Create a new authentication middleware with full RBAC support
    pub fn with_rbac(
        jwt_service: Arc<JwtService>,
        session_manager: Option<Arc<SessionManager>>,
        rbac_service: Arc<RBACService>,
    ) -> Self {
        Self {
            jwt_service,
            session_manager,
            rbac_service,
        }
    }

    /// Extract JWT token from request headers
    fn extract_token(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    }

    /// Extract session ID from cookies
    fn extract_session_id(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("cookie")
            .and_then(|h| h.to_str().ok())
            .and_then(|cookie_str| {
                cookie_str.split(';').find_map(|cookie| {
                    let cookie = cookie.trim();
                    if cookie.starts_with("aiviania_session=") {
                        Some(cookie.trim_start_matches("aiviania_session=").to_string())
                    } else {
                        None
                    }
                })
            })
    }

    /// Validate JWT token and return user information
    async fn validate_jwt(&self, token: &str) -> Result<User, AuthError> {
        let claims = self.jwt_service.validate_token(token)?;

        // Create user from claims
        let mut user = User::new(
            claims.username.clone(),
            claims.email.clone(),
            "".to_string(), // Password hash not needed for validation
        );
        user.id = claims.sub;

        // Add roles from claims
        for role_str in &claims.roles {
            match role_str.as_str() {
                "Admin" => user.add_role(crate::auth::models::Role::Admin),
                "Moderator" => user.add_role(crate::auth::models::Role::Moderator),
                "User" => user.add_role(crate::auth::models::Role::User),
                "Guest" => user.add_role(crate::auth::models::Role::Guest),
                custom => user.add_role(crate::auth::models::Role::Custom(custom.to_string())),
            }
        }

        // Add permissions from claims
        for perm_str in &claims.permissions {
            match perm_str.as_str() {
                "CreateUser" => user.add_permission(Permission::CreateUser),
                "ReadUser" => user.add_permission(Permission::ReadUser),
                "UpdateUser" => user.add_permission(Permission::UpdateUser),
                "DeleteUser" => user.add_permission(Permission::DeleteUser),
                "CreateContent" => user.add_permission(Permission::CreateContent),
                "ReadContent" => user.add_permission(Permission::ReadContent),
                "UpdateContent" => user.add_permission(Permission::UpdateContent),
                "DeleteContent" => user.add_permission(Permission::DeleteContent),
                "ManageUsers" => user.add_permission(Permission::ManageUsers),
                "ManageRoles" => user.add_permission(Permission::ManageRoles),
                "ViewAnalytics" => user.add_permission(Permission::ViewAnalytics),
                "SystemConfig" => user.add_permission(Permission::SystemConfig),
                "ApiAccess" => user.add_permission(Permission::ApiAccess),
                "WebSocketAccess" => user.add_permission(Permission::WebSocketAccess),
                custom => user.add_permission(Permission::Custom(custom.to_string())),
            }
        }

        Ok(user)
    }

    /// Validate session and return user information
    async fn validate_session(&self, session_id: &str) -> Result<User, AuthError> {
        if let Some(session_manager) = &self.session_manager {
            if let Some(session) = session_manager.get_session(session_id).await? {
                let mut user = User::new(
                    session.username,
                    "".to_string(), // Email not stored in session
                    "".to_string(),
                );
                user.id = session.user_id;

                // Add roles from session
                for role_str in &session.roles {
                    match role_str.as_str() {
                        "Admin" => user.add_role(crate::auth::models::Role::Admin),
                        "Moderator" => user.add_role(crate::auth::models::Role::Moderator),
                        "User" => user.add_role(crate::auth::models::Role::User),
                        "Guest" => user.add_role(crate::auth::models::Role::Guest),
                        custom => {
                            user.add_role(crate::auth::models::Role::Custom(custom.to_string()))
                        }
                    }
                }

                // Add permissions from session
                for perm_str in &session.permissions {
                    match perm_str.as_str() {
                        "CreateUser" => user.add_permission(Permission::CreateUser),
                        "ReadUser" => user.add_permission(Permission::ReadUser),
                        "UpdateUser" => user.add_permission(Permission::UpdateUser),
                        "DeleteUser" => user.add_permission(Permission::DeleteUser),
                        "CreateContent" => user.add_permission(Permission::CreateContent),
                        "ReadContent" => user.add_permission(Permission::ReadContent),
                        "UpdateContent" => user.add_permission(Permission::UpdateContent),
                        "DeleteContent" => user.add_permission(Permission::DeleteContent),
                        "ManageUsers" => user.add_permission(Permission::ManageUsers),
                        "ManageRoles" => user.add_permission(Permission::ManageRoles),
                        "ViewAnalytics" => user.add_permission(Permission::ViewAnalytics),
                        "SystemConfig" => user.add_permission(Permission::SystemConfig),
                        "ApiAccess" => user.add_permission(Permission::ApiAccess),
                        "WebSocketAccess" => user.add_permission(Permission::WebSocketAccess),
                        custom => user.add_permission(Permission::Custom(custom.to_string())),
                    }
                }

                Ok(user)
            } else {
                Err(AuthError::InvalidSession)
            }
        } else {
            Err(AuthError::SessionNotSupported)
        }
    }

    /// Check if user has required permission
    #[allow(dead_code)]
    fn check_permission(
        &self,
        user: &User,
        required_permission: Option<&Permission>,
    ) -> Result<(), AuthError> {
        if let Some(permission) = required_permission {
            if !self.rbac_service.has_permission(user, permission) {
                return Err(AuthError::InsufficientPermissions);
            }
        }
        Ok(())
    }
}

impl Middleware for AuthMiddleware {
    fn before(
        &self,
        req: Request<hyper::Body>,
    ) -> Pin<
        Box<dyn std::future::Future<Output = MiddlewareResult<Request<hyper::Body>>> + Send + '_>,
    > {
        let self_clone = self;
        Box::pin(async move {
            // Try JWT token first
            if let Some(token) = self_clone.extract_token(req.headers()) {
                match self_clone.validate_jwt(&token).await {
                    Ok(user) => {
                        // Store user in request extensions
                        let mut req = req;
                        req.extensions_mut().insert(user);
                        return Ok(req);
                    }
                    Err(_) => {
                        // JWT failed, try session if available
                    }
                }
            }

            // Try session authentication
            if let Some(session_id) = self_clone.extract_session_id(req.headers()) {
                if let Ok(user) = self_clone.validate_session(&session_id).await {
                    let mut req = req;
                    req.extensions_mut().insert(user);
                    return Ok(req);
                }
            }

            // No valid authentication found
            Err(self_clone.create_unauthorized_response())
        })
    }

    fn after(
        &self,
        resp: Response<hyper::Body>,
    ) -> Pin<Box<dyn std::future::Future<Output = Response<hyper::Body>> + Send + '_>> {
        Box::pin(async move {
            // No modifications needed for auth middleware
            resp
        })
    }
}

impl AuthMiddleware {
    /// Create unauthorized response
    fn create_unauthorized_response(&self) -> Response<hyper::Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(hyper::Body::from(
                r#"{"error": "Unauthorized", "message": "Authentication required"}"#,
            ))
            .unwrap()
    }

    /// Create forbidden response
    #[allow(dead_code)]
    fn create_forbidden_response(&self) -> Response<hyper::Body> {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(hyper::Body::from(
                r#"{"error": "Forbidden", "message": "Insufficient permissions"}"#,
            ))
            .unwrap()
    }
}

/// Authentication errors
#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("JWT validation failed: {0}")]
    JwtError(#[from] crate::auth::jwt::JwtError),

    #[error("Session validation failed: {0}")]
    SessionError(#[from] crate::auth::session::SessionError),

    #[error("Invalid session")]
    InvalidSession,

    #[error("Session authentication not supported")]
    SessionNotSupported,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Authentication required")]
    AuthenticationRequired,
}

/// Helper function to get authenticated user from request
pub fn get_authenticated_user(req: &Request<hyper::Body>) -> Result<&User, AuthError> {
    req.extensions()
        .get::<User>()
        .ok_or(AuthError::AuthenticationRequired)
}

/// Helper function to check permission for authenticated user
pub fn check_user_permission(
    req: &Request<hyper::Body>,
    permission: &Permission,
    rbac_service: &RBACService,
) -> Result<(), AuthError> {
    let user = get_authenticated_user(req)?;
    if !rbac_service.has_permission(user, permission) {
        return Err(AuthError::InsufficientPermissions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use hyper::{Body, Method, Request};

    #[tokio::test]
    async fn test_jwt_authentication() {
        let jwt_service = Arc::new(JwtService::default());
        let middleware = AuthMiddleware::new(jwt_service.clone());

        // Create a test token
        let token = jwt_service
            .create_access_token(
                "user123",
                "testuser",
                "test@example.com",
                &["User".to_string()],
                &["ApiAccess".to_string()],
            )
            .unwrap();

        // Create request with token
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        // Test middleware
        let result = middleware.before(req).await;
        assert!(result.is_ok());

        let req = result.unwrap();
        let user = get_authenticated_user(&req).unwrap();
        assert_eq!(user.id, "user123");
        assert_eq!(user.username, "testuser");
    }

    #[tokio::test]
    async fn test_no_authentication() {
        let jwt_service = Arc::new(JwtService::default());
        let middleware = AuthMiddleware::new(jwt_service);

        // Create request without authentication
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();

        // Test middleware
        let result = middleware.before(req).await;
        assert!(result.is_err());
    }
}
