//! Authentication and Authorization module.
//!
//! This module provides comprehensive authentication and authorization features:
//! - JWT token-based authentication
//! - Session management
//! - Role-based access control (RBAC)
//! - Password hashing and verification
//! - Authentication middleware

pub mod jwt;
pub mod middleware;
pub mod models;
pub mod password;
pub mod rbac;
pub mod session;

// Re-export commonly used types
pub use jwt::{Claims, JwtService};
pub use middleware::AuthMiddleware;
pub use models::{Permission, Role, User, UserRole};
pub use password::PasswordService;
pub use rbac::RBACService;
pub use session::SessionManager;
// Note: AuthService wrapper is provided below for backwards compatibility.

// Compatibility handlers for examples (minimal stubs that compile)
pub mod compat;
pub use compat::{login_handler, register_handler};

/// Backwards-compatible AuthService wrapper so examples that expect an
/// `AuthService` value (and sometimes add it as a plugin) can continue to work.
pub struct AuthServiceWrapper {
	inner: std::sync::Arc<JwtService>,
}

impl AuthServiceWrapper {
	pub fn new(secret: &str) -> Self {
		let config = crate::auth::jwt::JwtConfig {
			secret: secret.to_string(),
			..Default::default()
		};
		Self {
			inner: std::sync::Arc::new(JwtService::new(config)),
		}
	}

	/// Get inner Arc<JwtService>
	pub fn inner(&self) -> std::sync::Arc<JwtService> {
		self.inner.clone()
	}
}

impl crate::plugin::Plugin for AuthServiceWrapper {
	fn as_any(&self) -> &dyn std::any::Any {
		self
	}

	fn name(&self) -> &'static str {
		"auth"
	}
}

// Note: do not implement foreign trait for foreign type; use AuthMiddleware::from_auth_service
// helper instead when passing the backwards-compatible AuthService wrapper.

// Re-export the wrapper under the name AuthService for examples that expect it
pub use AuthServiceWrapper as AuthService;
