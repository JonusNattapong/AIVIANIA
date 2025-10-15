//! AIVIANIA: Minimal async-first Rust Web Framework prototype
//! Core library entry point. Re-exports main modules for developer ergonomics.

#[cfg(feature = "ai_ml")]
pub mod ai_ml;
pub mod auth;
pub mod blockchain;
pub mod config;
pub mod database;
#[cfg(feature = "utoipa")]
pub mod docs;
pub mod email;
pub mod errors;
pub mod graphql;
pub mod jobs;
pub mod metrics;
pub mod middleware;
pub mod middleware_ext;
pub mod oauth;
pub mod plugin;
pub mod rate_limit;
pub mod request;
pub mod response;
pub mod router;
pub mod security;
pub mod security_example;
pub mod server;
pub mod session;
pub mod upload;
pub mod websocket;

// Re-export commonly used types for convenience
pub use auth::{
    AuthMiddleware, Claims, JwtService, PasswordService, Permission, RBACService, Role, User,
};
pub use blockchain::{BlockchainClient, BlockchainPlugin};
pub use config::AppConfig;
pub use database::repositories::User as DbUser;
pub use database::{
    DatabaseConfig, DatabaseConnection, DatabaseError, DatabaseManager, DatabaseType, Migration,
    Repository, Transaction,
};
#[cfg(feature = "utoipa")]
pub use docs::{openapi_spec, swagger_ui};
pub use email::{
    EmailConfig, EmailError, EmailService, EmailVerificationService, PasswordResetService,
};
pub use graphql::{
    graphql_handler, graphql_playground, GraphQLConfig, GraphQLContext, GraphQLMiddleware,
    GraphQLSchema, GraphQLService,
};
#[cfg(feature = "redis")]
pub use jobs::RedisJobQueue;
pub use jobs::{Job, JobManager, JobPriority, JobStatus, JobWorker, MemoryJobQueue};
pub use middleware::Middleware;
pub use oauth::{OAuthConfig, OAuthError, OAuthMiddleware, OAuthService, OAuthTokens, OAuthUser};
pub use plugin::Plugin;
pub use request::AivianiaRequest as Request;
pub use response::AivianiaResponse as Response;
pub use router::{Route, Router};
pub use security::{
    CorsMiddleware, CsrfProtection, EventExporter, EventFilter, InputValidator, SecurityAlert,
    SecurityAlertSystem, SecurityConfig, SecurityError, SecurityEvent, SecurityEventLogger,
    SecurityHeadersMiddleware, SecurityMetrics, SecurityMetricsCalculator, SecurityMiddlewareStack,
    SecuritySeverity,
};
pub use server::AivianiaServer;
#[cfg(feature = "redis")]
pub use session::RedisSessionStore;
pub use session::{MemorySessionStore, SessionData, SessionManager, SessionMiddleware};
pub use upload::{
    extract_and_store_files, get_uploaded_files, UploadConfig, UploadError, UploadManager,
    UploadMiddleware, UploadedFile,
};
pub use websocket::{WebSocketManager, WebSocketPlugin};
