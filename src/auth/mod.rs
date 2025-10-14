//! Authentication and Authorization module.
//!
//! This module provides comprehensive authentication and authorization features:
//! - JWT token-based authentication
//! - Session management
//! - Role-based access control (RBAC)
//! - Password hashing and verification
//! - Authentication middleware

pub mod jwt;
pub mod session;
pub mod rbac;
pub mod middleware;
pub mod models;
pub mod password;

// Re-export commonly used types
pub use jwt::{JwtService, Claims};
pub use session::SessionManager;
pub use rbac::RBACService;
pub use middleware::AuthMiddleware;
pub use models::{User, Role, Permission, UserRole};
pub use password::PasswordService;