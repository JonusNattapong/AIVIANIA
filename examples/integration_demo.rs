use aiviania::rate_limit::{KeyStrategy, RateLimitConfig, RateLimitMiddleware};
use aiviania::response::AivianiaResponse;
use aiviania::router::{Route, Router};
use aiviania::server::AivianiaServer;
use aiviania::websocket::{WSMessage, WebSocketManager};
use hyper::{Body, Request as HyperRequest, StatusCode};
use serde_json::json;
use std::sync::Arc;

/// Comprehensive integration example demonstrating WebSocket, Rate Limiting, and API Documentation
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting AIVIANIA Integration Demo");
    println!("Features: WebSocket Rooms, Rate Limiting, OpenAPI Documentation");

    // Initialize services
    let ws_manager = Arc::new(WebSocketManager::new());
    let rate_limiter = RateLimitMiddleware::new(RateLimitConfig {
        requests_per_window: 50,
        window_duration: std::time::Duration::from_secs(60),
        key_strategy: KeyStrategy::IP,
        use_redis: false,
    });

    // Create router
    let mut router = Router::new();

    // WebSocket routes with room support
    let ws_manager_clone = ws_manager.clone();
    router.add_route(Route::new(
        "GET",
        "/ws/:room_id",
        move |req: HyperRequest<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| {
            let ws_manager = ws_manager_clone.clone();
            async move {
                let path = req.uri().path();
                let room_id = path.split('/').last().unwrap_or("general").to_string();

                println!("🔌 WebSocket connection request for room: {}", room_id);

                match ws_manager.handle_upgrade(req, Some(room_id)).await {
                    Ok(response) => {
                        println!("✅ WebSocket upgrade successful");
                        // Convert HyperResponse to AivianiaResponse
                        // For WebSocket upgrade, we need to preserve the special headers
                        let status = response.status();
                        let mut aiviania_resp = AivianiaResponse::new(status);

                        // Copy all headers from the WebSocket response
                        for (key, value) in response.headers() {
                            if let Ok(value_str) = value.to_str() {
                                aiviania_resp = aiviania_resp.header(key.as_str(), value_str);
                            }
                        }

                        aiviania_resp
                    }
                    Err(e) => {
                        println!("❌ WebSocket upgrade failed: {:?}", e);
                        AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
        },
    ));

    // Room messaging API
    let ws_manager_clone = ws_manager.clone();
    router.add_route(Route::new(
        "POST",
        "/api/rooms/:room_id/message",
        move |req: HyperRequest<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| {
            let ws_manager = ws_manager_clone.clone();
            async move {
                let path = req.uri().path();
                let room_id = path.split('/').nth(3).unwrap_or("general").to_string();

                // Parse JSON body
                let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
                    Ok(bytes) => bytes,
                    Err(_) => return AivianiaResponse::new(StatusCode::BAD_REQUEST),
                };

                let message_data: serde_json::Value = match serde_json::from_slice(&body_bytes) {
                    Ok(data) => data,
                    Err(_) => return AivianiaResponse::new(StatusCode::BAD_REQUEST),
                };

                let ws_message = WSMessage::RoomMessage {
                    room: room_id.clone(),
                    message: message_data
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                };

                println!(
                    "📤 Broadcasting message to room {}: {:?}",
                    room_id, ws_message
                );
                let _ = ws_manager
                    .broadcast_to_room(&room_id, &format!("{:?}", ws_message), None)
                    .await;

                AivianiaResponse::new(StatusCode::OK).json(&json!({
                    "status": "sent",
                    "room_id": room_id,
                    "message_type": "chat"
                }))
            }
        },
    ));

    // Room information API
    let ws_manager_clone = ws_manager.clone();
    router.add_route(Route::new(
        "GET",
        "/api/rooms/:room_id/info",
        move |req: HyperRequest<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| {
            let ws_manager = ws_manager_clone.clone();
            async move {
                let path = req.uri().path();
                let room_id = path.split('/').nth(3).unwrap_or("general").to_string();

                let room_info = ws_manager.get_room_info(&room_id).await;

                println!(
                    "📊 Room {} info requested: {} users",
                    room_id, room_info.user_count
                );

                AivianiaResponse::new(StatusCode::OK)
                    .header("content-type", "application/json")
                    .json(&room_info)
            }
        },
    ));

    // Health check endpoint (not rate limited)
    router.add_route(Route::new(
        "GET",
        "/health",
        |_req: HyperRequest<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| async move {
            println!("💚 Health check requested");

            AivianiaResponse::new(StatusCode::OK).json(&json!({
                "status": "healthy",
                "features": ["websocket", "rate_limiting"],
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        },
    ));

    // Rate limiting test endpoint
    router.add_route(Route::new(
        "GET",
        "/api/test-rate-limit",
        |_req: HyperRequest<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| async move {
            println!("🛡️ Rate limited endpoint accessed");

            AivianiaResponse::new(StatusCode::OK).json(&json!({
                "message": "Request allowed",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        },
    ));

    println!("📋 Available endpoints:");
    println!("  🔌 WebSocket: ws://127.0.0.1:3000/ws/{{room_id}}");
    println!("  📤 Send Message: POST /api/rooms/{{room_id}}/message");
    println!("  📊 Room Info: GET /api/rooms/{{room_id}}/info");
    println!("  💚 Health Check: GET /health");
    println!("  🛡️ Rate Limit Test: GET /api/test-rate-limit");
    println!();
    println!("🚀 Server starting on http://127.0.0.1:3000");

    // Create server with middleware
    let server = AivianiaServer::new(router).with_middleware(Box::new(rate_limiter));

    // Start the server
    server.run("127.0.0.1:3000").await?;

    Ok(())
}
