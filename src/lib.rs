//! AIVIANIA: Minimal async-first Rust Web Framework prototype
//! Core library entry point. Re-exports main modules for developer ergonomics.

pub mod server;
pub mod router;
pub mod request;
pub mod response;
pub mod middleware;
pub mod middleware_ext;
pub mod metrics;
pub mod auth;
pub mod database;
pub mod websocket;
pub mod config;
pub mod errors;
pub mod rate_limit;
#[cfg(feature = "ai_ml")]
pub mod ai_ml;
pub mod plugin;
pub mod blockchain;
#[cfg(feature = "utoipa")]
pub mod docs;
pub mod session;
pub mod jobs;
pub mod upload;
pub mod email;
pub mod graphql;
pub mod oauth;
pub mod security_example;
pub mod security;

// Re-export commonly used types for convenience
pub use server::AivianiaServer;
pub use router::{Route, Router};
pub use request::AivianiaRequest as Request;
pub use response::AivianiaResponse as Response;
pub use middleware::Middleware;
pub use plugin::Plugin;
pub use config::AppConfig;
pub use auth::{JwtService, RBACService, AuthMiddleware, User, Role, Permission, PasswordService, Claims};
pub use database::{DatabaseManager, DatabaseConfig, DatabaseType, DatabaseError, DatabaseConnection, Transaction, Migration, Repository};
pub use database::repositories::User as DbUser;
pub use websocket::{WebSocketManager, WebSocketPlugin};
pub use blockchain::{BlockchainClient, BlockchainPlugin};
#[cfg(feature = "utoipa")]
pub use docs::{swagger_ui, openapi_spec};
pub use session::{SessionManager, SessionMiddleware, SessionData, MemorySessionStore};
#[cfg(feature = "redis")]
pub use session::RedisSessionStore;
pub use jobs::{JobManager, JobWorker, Job, JobPriority, JobStatus, MemoryJobQueue};
#[cfg(feature = "redis")]
pub use jobs::RedisJobQueue;
pub use upload::{UploadManager, UploadConfig, UploadedFile, UploadError, UploadMiddleware, get_uploaded_files, extract_and_store_files};
pub use email::{EmailService, EmailConfig, EmailError, EmailVerificationService, PasswordResetService};
pub use graphql::{GraphQLService, GraphQLConfig, GraphQLSchema, GraphQLContext, GraphQLMiddleware, graphql_handler, graphql_playground};
pub use oauth::{OAuthService, OAuthConfig, OAuthUser, OAuthTokens, OAuthError, OAuthMiddleware};
pub use security::{SecurityConfig, CsrfProtection, CorsMiddleware, SecurityHeadersMiddleware, InputValidator, SecurityEventLogger, SecurityMiddlewareStack, SecurityEvent, SecuritySeverity, SecurityError, EventFilter, EventExporter, SecurityMetricsCalculator, SecurityMetrics, SecurityAlertSystem, SecurityAlert};
