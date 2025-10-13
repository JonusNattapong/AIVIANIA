//! AIVIANIA: Minimal async-first Rust Web Framework prototype
//! Core library entry point. Re-exports main modules for developer ergonomics.

pub mod server;
pub mod router;
pub mod request;
pub mod response;
pub mod middleware;
pub mod middleware_ext;
pub mod plugin;
pub mod auth;
pub mod database;
pub mod websocket;
pub mod config;
pub mod errors;
pub mod rate_limit;
pub mod cache;
pub mod metrics;
pub mod blockchain;
#[cfg(feature = "utoipa")]
pub mod docs;
pub mod session;

// Re-export commonly used types for convenience
pub use server::AivianiaServer;
pub use router::{Route, Router};
pub use request::AivianiaRequest as Request;
pub use response::AivianiaResponse as Response;
pub use middleware::Middleware;
pub use plugin::Plugin;
pub use config::AppConfig;
pub use auth::{AuthService, AuthMiddleware, login_handler, register_handler, LoginRequest, RegisterRequest};
pub use database::{Database, DatabasePlugin, User};
pub use websocket::{WebSocketHandler, WebSocketPlugin};
pub use blockchain::{BlockchainClient, BlockchainPlugin};
#[cfg(feature = "utoipa")]
pub use docs::{swagger_ui, openapi_spec};
pub use session::{SessionManager, SessionMiddleware, SessionData, MemorySessionStore};
#[cfg(feature = "redis")]
pub use session::RedisSessionStore;
