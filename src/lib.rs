//! AIVIANIA: Minimal async-first Rust Web Framework prototype
//! Core library entry point. Re-exports main modules for developer ergonomics.

pub mod server;
pub mod router;
pub mod request;
pub mod response;
pub mod middleware;
pub mod plugin;
pub mod auth;
pub mod database;
pub mod websocket;

// Re-export commonly used types for convenience
pub use server::AivianiaServer;
pub use router::{Route, Router};
pub use request::AivianiaRequest as Request;
pub use response::AivianiaResponse as Response;
pub use middleware::Middleware;
pub use plugin::Plugin;
pub use auth::{AuthService, AuthMiddleware, login_handler};
pub use database::{Database, DatabasePlugin, User};
pub use websocket::{WebSocketHandler, WebSocketPlugin};
