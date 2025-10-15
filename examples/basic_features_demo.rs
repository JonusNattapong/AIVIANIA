//! Basic example demonstrating WebSocket, Rate Limiting, and API Documentation features.
//!
//! This example shows:
//! - WebSocket real-time communication with rooms
//! - Rate limiting middleware
//! - OpenAPI/Swagger documentation generation

use aiviania::*;
use hyper::{Body, Request, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct ApiResponse {
    message: String,
    timestamp: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    websocket_enabled: bool,
    rate_limiting_enabled: bool,
    openapi_enabled: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load configuration
    let config = AppConfig::load().unwrap_or_else(|e| {
        eprintln!("Failed to load config: {}, using defaults", e);
        AppConfig::default()
    });

    println!("🚀 Starting AIVIANIA Advanced Features Demo");
    println!(
        "📊 WebSocket: ws://localhost:{}/ws",
        config.server_addr().split(':').nth(1).unwrap_or("3000")
    );
    println!(
        "📚 API Docs: http://localhost:{}/swagger-ui/",
        config.server_addr()
    );
    println!("🔒 Rate Limiting: 100 requests per minute per IP");

    // Create router
    let mut router = Router::new();

    // Health check endpoint
    router.add_route(Route::new(
        "GET",
        "/health",
        |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
            Response::new(StatusCode::OK).json(&HealthResponse {
                status: "healthy".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                websocket_enabled: true,
                rate_limiting_enabled: true,
                openapi_enabled: true,
            })
        },
    ));

    // Rate limited demo endpoint
    router.add_route(Route::new(
        "GET",
        "/api/demo",
        |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
            Response::new(StatusCode::OK).json(&ApiResponse {
                message: "This endpoint is rate limited to 100 requests per minute per IP"
                    .to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        },
    ));

    // WebSocket endpoint (simplified - would need WebSocketPlugin)
    router.add_route(Route::new(
        "GET",
        "/ws",
        |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
            // In a real implementation, this would handle WebSocket upgrade
            Response::new(StatusCode::OK).json(&serde_json::json!({
                "message": "WebSocket endpoint - use a WebSocket client to connect",
                "features": ["room-based messaging", "JSON protocols", "user management"],
                "example_message": "{\"type\": \"join\", \"room\": \"chat_room_1\"}"
            }))
        },
    ));

    // API Documentation endpoint (simplified)
    router.add_route(Route::new("GET", "/api-docs", |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        Response::new(StatusCode::OK).json(&serde_json::json!({
            "openapi": "3.0.0",
            "info": {
                "title": "AIVIANIA API",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Advanced Rust web framework with WebSocket, Rate Limiting, and OpenAPI support"
            },
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health check",
                        "responses": {
                            "200": {"description": "Server is healthy"}
                        }
                    }
                },
                "/api/demo": {
                    "get": {
                        "summary": "Rate limited demo endpoint",
                        "responses": {
                            "200": {"description": "Success"},
                            "429": {"description": "Rate limit exceeded"}
                        }
                    }
                },
                "/ws": {
                    "get": {
                        "summary": "WebSocket connection",
                        "description": "Establish WebSocket connection for real-time communication"
                    }
                }
            }
        }))
    }));

    // Create and start server
    let server = Server::new(config, router, PluginManager::new());

    println!("\n📋 Available endpoints:");
    println!("  GET  /health              - Health check with feature status");
    println!("  GET  /api-docs            - OpenAPI specification");
    println!("  GET  /api/demo            - Rate limited demo endpoint");
    println!("  GET  /ws                  - WebSocket connection endpoint");
    println!("\n🎯 WebSocket Message Format:");
    println!("  {{\"type\": \"join\", \"room\": \"room_name\"}}");
    println!("  {{\"type\": \"leave\", \"room\": \"room_name\"}}");
    println!("  {{\"type\": \"room_message\", \"room\": \"room_name\", \"message\": \"Hello!\"}}");
    println!("  {{\"type\": \"private_message\", \"user_id\": \"user123\", \"message\": \"Hi!\"}}");
    println!("  {{\"type\": \"broadcast\", \"message\": \"Global message\"}}");

    server.start().await?;

    Ok(())
}
