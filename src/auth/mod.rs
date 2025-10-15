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
