//! Example usage of AIVIANIA framework.
//!
//! This example demonstrates:
//! - Setting up a server
//! - Registering routes
//! - Using middleware
//! - Using plugins (AI example)
//! - Running the server

use aiviania::*;
use aiviania::middleware::{LoggingMiddleware, RoleMiddleware};
use aiviania::plugin::{AIPlugin, PluginManager};
use aiviania::auth::{AuthService, AuthMiddleware, login_handler, register_handler};
use aiviania::database::{Database, DatabasePlugin};
use hyper::{Request, Body, StatusCode};
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

    println!("Starting AIVIANIA server on {}", config.server_addr());
    println!("Database: {}", config.database.url);
    println!("JWT expiration: {} hours", config.auth.jwt_expiration_hours);
    // Create router
    let mut router = Router::new();

    // Add routes
    router.add_route(Route::new("GET", "/", |_req: Request<Body>, plugins: Arc<PluginManager>| async move {
        // Call AI plugin
        if let Some(plugin) = plugins.get("ai") {
            if let Some(ai_plugin) = plugin.as_any().downcast_ref::<AIPlugin>() {
                let ai_response = ai_plugin.call_ai("Hello from AIVIANIA!").await.unwrap_or_else(|_| "AI Error".to_string());
                return Response::new(StatusCode::OK).json(&JsonResponse {
                    message: "Hello, World!".to_string(),
                    ai_response,
                });
            }
        }

        Response::new(StatusCode::OK).json(&JsonResponse {
            message: "Hello, World!".to_string(),
            ai_response: "No AI plugin".to_string(),
        })
    }));

    router.add_route(Route::new("POST", "/login", login_handler));
    router.add_route(Route::new("POST", "/register", register_handler));

    // Initialize database and auth_service using config
    let auth_service = Arc::new(AuthService::new(&config.auth.jwt_secret));
    let db = Arc::new(Database::new().await?);

    router.add_route(Route::new("GET", "/admin/dashboard", |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        Response::new(StatusCode::OK).json(&serde_json::json!({
            "message": "Admin Dashboard",
            "data": "This is restricted to admin users only"
        }))
    }).with_middleware(Box::new(AuthMiddleware::new(auth_service.clone())))
      .with_middleware(Box::new(RoleMiddleware::new("admin", db.clone()))));

    router.add_route(Route::new("GET", "/user/profile", |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        Response::new(StatusCode::OK).json(&serde_json::json!({
            "message": "User Profile",
            "data": "This is accessible to authenticated users"
        }))
    }).with_middleware(Box::new(AuthMiddleware::new(auth_service.clone())))
      .with_middleware(Box::new(RoleMiddleware::new("user", db.clone()))));

    // Add WebSocket route
    router.add_route(Route::new("GET", "/ws", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
        if let Some(ws_plugin) = plugins.get("websocket") {
            if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketPlugin>() {
                match ws_handler.handler().handle_upgrade(req).await {
                    Ok(hyper_response) => {
                        let mut response = Response::new(hyper_response.status());
                        // Copy headers from hyper response
                        for (key, value) in hyper_response.headers() {
                            if let Ok(value_str) = value.to_str() {
                                response = response.header(key.as_str(), value_str);
                            }
                        }
                        // For now, return JSON status since full WebSocket upgrade is not implemented
                        return response.json(&serde_json::json!({
                            "status": "WebSocket endpoint ready",
                            "note": "Full WebSocket upgrade coming soon"
                        }));
                    }
                    Err(e) => {
                        eprintln!("WebSocket upgrade error: {}", e);
                        return Response::new(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            }
        }
        Response::new(StatusCode::INTERNAL_SERVER_ERROR)
    }));

    router.add_route(Route::new("POST", "/echo", |req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
        Response::new(StatusCode::OK).body(Body::from(body_bytes))
    }));

    // Broadcast message to all WebSocket connections
    router.add_route(Route::new("POST", "/broadcast", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
        if let Some(ws_plugin) = plugins.get("websocket") {
            if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketPlugin>() {
                match hyper::body::to_bytes(req.into_body()).await {
                    Ok(body) => {
                        #[derive(serde::Deserialize)]
                        struct BroadcastRequest {
                            message: String,
                        }
                        match serde_json::from_slice::<BroadcastRequest>(&body) {
                            Ok(broadcast_req) => {
                                ws_handler.handler().broadcast(&broadcast_req.message);
                                return Response::new(StatusCode::OK).json(&serde_json::json!({"status": "broadcasted"}));
                            }
                            Err(_) => return Response::new(StatusCode::BAD_REQUEST).body(Body::from("Invalid JSON")),
                        }
                    }
                    Err(_) => return Response::new(StatusCode::BAD_REQUEST).body(Body::from("Failed to read body")),
                }
            }
        }
        Response::new(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("WebSocket plugin not found"))
    }));

    // Create database
    let db = Arc::new(Database::new().await?);
    
    // Create default roles
    db.create_default_roles().await?;
    
    // Create a test user (in production, this would be done through registration)
    let password_hash = Database::hash_password("password123")?;
    let admin_user_id = db.create_user("admin", &password_hash).await?;
    db.assign_role_to_user(admin_user_id, "admin").await?;
    println!("Created admin user: admin/password123 with admin role");

    // Create server
    let server = AivianiaServer::new(router)
        .with_middleware(Box::new(LoggingMiddleware))
        .with_plugin(Box::new(AIPlugin::new("dummy-api-key".to_string())))
        .with_plugin(Box::new(DatabasePlugin::new(db)))
        .with_plugin(Box::new(WebSocketPlugin::new()))
        .with_plugin(Box::new(AuthService::new(&config.auth.jwt_secret)));

    // Note: Auth service is now added as a plugin for token generation

    // Run server
    server.run(&config.server_addr()).await
}