//! AIVIANIA Development Server
//!
//! This is the main binary entry point for development.
//! It starts a basic server with common features enabled.

use aiviania::auth::{login_handler, register_handler, AuthMiddleware, AuthService};
use aiviania::database::{Database, DatabasePlugin};
use aiviania::middleware::{LoggingMiddleware, RoleMiddleware};
use aiviania::plugin::{AIPlugin, PluginManager};
use aiviania::*;
use hyper::{Body, Request, StatusCode};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct JsonResponse {
    message: String,
    ai_response: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load configuration
    let config = AppConfig::load().unwrap_or_else(|e| {
        eprintln!("Failed to load config: {}, using defaults", e);
        AppConfig::default()
    });

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration validation failed: {}", e);
        std::process::exit(1);
    }

    println!("🚀 Starting AIVIANIA Development Server");
    println!("=====================================");
    println!("Server: http://{}", config.server_addr());
    println!("Database: {}", config.database.url);
    println!("JWT expiration: {} hours", config.auth.jwt_expiration_hours);

    // Initialize database and auth service
    let jwt_config = aiviania::auth::jwt::JwtConfig {
        secret: config.auth.jwt_secret.clone(),
        ..Default::default()
    };
    let auth_service = Arc::new(AuthService::new(&jwt_config.secret));
    let db = Arc::new(Database::new_from_config(&config).await?);

    // Create default roles
    db.create_default_roles().await?;
    println!("✅ Default roles created");

    // Create router
    let mut router = Router::new();

    // Add authentication routes
    router.add_route(Route::new("POST", "/register", register_handler));
    router.add_route(Route::new("POST", "/login", login_handler));

    // Add public routes
    router.add_route(Route::new(
        "GET",
        "/",
        |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
            Response::new(StatusCode::OK).json(&serde_json::json!({
                "message": "Welcome to AIVIANIA!",
                "version": env!("CARGO_PKG_VERSION"),
                "status": "running"
            }))
        },
    ));

    // Add protected routes with middleware
    router.add_route(
        Route::new(
            "GET",
            "/profile",
            |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
                Response::new(StatusCode::OK).json(&serde_json::json!({
                    "message": "Profile accessed successfully",
                    "user_id": "authenticated"
                }))
            },
        )
        .with_middleware(Box::new(AuthMiddleware::from_auth_service(auth_service.clone()))),
    );

    router.add_route(
        Route::new(
            "GET",
            "/admin/dashboard",
            |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
                Response::new(StatusCode::OK).json(&serde_json::json!({
                    "message": "Admin dashboard accessed",
                    "role": "admin"
                }))
            },
        )
        .with_middleware(Box::new(AuthMiddleware::from_auth_service(auth_service.clone())))
        .with_middleware(Box::new(RoleMiddleware::for_db("admin", db.clone()))),
    );

    // Create server
    let server = AivianiaServer::new(router)
        .with_middleware(Box::new(LoggingMiddleware))
        .with_plugin(Box::new(DatabasePlugin::new(db)))
        .with_plugin(Box::new(AIPlugin::new("your-openai-api-key-here".to_string())));

    println!("✅ Server configured and ready");
    println!("📡 Listening on http://{}", config.server_addr());
    println!("=====================================");

    // Start server
    server.run(&config.server_addr()).await?;

    Ok(())
}