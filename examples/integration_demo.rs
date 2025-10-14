use aiviania::framework::{AivianiaApp, Route};
use aiviania::websocket::{WebSocketManager, WSMessage, MessageType};
use aiviania::rate_limit::{RateLimitMiddleware, RateLimitBuilder, KeyStrategy};
use aiviania::openapi::{OpenApiService, OpenApiConfig};
use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;
use serde_json::json;

/// Comprehensive integration example demonstrating WebSocket, Rate Limiting, and API Documentation
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting AIVIANIA Integration Demo");
    println!("Features: WebSocket Rooms, Rate Limiting, OpenAPI Documentation");

    // Initialize the application
    let mut app = AivianiaApp::new();

    // Initialize services
    let ws_manager = Arc::new(WebSocketManager::new());
    let rate_limiter = Arc::new(RateLimitMiddleware::new(
        RateLimitBuilder::new()
            .with_capacity(50)
            .with_refill_rate(10)
            .with_window_secs(60)
            .with_key_strategy(KeyStrategy::IpAddress)
            .build()
    ));

    let openapi_config = OpenApiConfig {
        title: "AIVIANIA Integration Demo API".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Demonstration of WebSocket, Rate Limiting, and API Documentation".to_string()),
        ..Default::default()
    };
    let openapi_service = Arc::new(OpenApiService::new(openapi_config));

    // Add middleware
    app.add_middleware(rate_limiter);

    // WebSocket routes with room support
    app.add_route(Route::new("GET", "/ws/:room_id", move |req: Request<Body>| {
        let ws_manager = ws_manager.clone();
        async move {
            let path = req.uri().path();
            let room_id = path.split('/').last().unwrap_or("general").to_string();

            println!("🔌 WebSocket connection request for room: {}", room_id);

            match ws_manager.handle_upgrade(req, Some(room_id)).await {
                Ok(response) => {
                    println!("✅ WebSocket upgrade successful");
                    response
                },
                Err(e) => {
                    println!("❌ WebSocket upgrade failed: {:?}", e);
                    Response::new(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
    }));

    // Room messaging API
    app.add_route(Route::new("POST", "/api/rooms/:room_id/message", move |req: Request<Body>| {
        let ws_manager = ws_manager.clone();
        async move {
            let path = req.uri().path();
            let room_id = path.split('/').nth(3).unwrap_or("general").to_string();

            // Parse JSON body
            let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
                Ok(bytes) => bytes,
                Err(_) => return Response::new(StatusCode::BAD_REQUEST),
            };

            let message_data: serde_json::Value = match serde_json::from_slice(&body_bytes) {
                Ok(data) => data,
                Err(_) => return Response::new(StatusCode::BAD_REQUEST),
            };

            let ws_message = WSMessage {
                message_type: MessageType::Chat,
                room_id: Some(room_id.clone()),
                user_id: message_data.get("user_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                content: message_data.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                timestamp: chrono::Utc::now(),
                metadata: message_data.get("metadata").cloned(),
            };

            println!("📤 Broadcasting message to room {}: {}", room_id, ws_message.content);
            ws_manager.broadcast_to_room(&room_id, &ws_message).await;

            Response::new(StatusCode::OK).json(&json!({
                "status": "sent",
                "room_id": room_id,
                "message_type": "chat"
            }))
        }
    }));

    // Room information API
    app.add_route(Route::new("GET", "/api/rooms/:room_id/info", move |req: Request<Body>| {
        let ws_manager = ws_manager.clone();
        async move {
            let path = req.uri().path();
            let room_id = path.split('/').nth(3).unwrap_or("general").to_string();

            let room_info = ws_manager.get_room_info(&room_id).await;

            println!("📊 Room {} info requested: {} users", room_id, room_info.user_count);

            Response::new(StatusCode::OK).json(&room_info)
        }
    }));

    // API Documentation routes
    app.add_route(Route::new("GET", "/api-docs/openapi.json", move |req: Request<Body>| {
        let openapi_service = openapi_service.clone();
        async move {
            println!("📄 OpenAPI JSON specification requested");

            let spec = openapi_service.generate_spec().await;
            Response::new(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(spec))
        }
    }));

    app.add_route(Route::new("GET", "/api-docs", move |req: Request<Body>| {
        let openapi_service = openapi_service.clone();
        async move {
            println!("📖 Swagger UI requested");

            let html = openapi_service.generate_swagger_ui("/api-docs/openapi.json");
            Response::new(StatusCode::OK)
                .header("content-type", "text/html")
                .body(Body::from(html))
        }
    }));

    // Health check endpoint (not rate limited)
    app.add_route(Route::new("GET", "/health", |req: Request<Body>| async move {
        println!("💚 Health check requested");

        Response::new(StatusCode::OK).json(&json!({
            "status": "healthy",
            "features": ["websocket", "rate_limiting", "api_docs"],
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }));

    // Rate limiting test endpoint
    app.add_route(Route::new("GET", "/api/test-rate-limit", |req: Request<Body>| async move {
        println!("🛡️ Rate limited endpoint accessed");

        Response::new(StatusCode::OK).json(&json!({
            "message": "Request allowed",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }));

    println!("📋 Available endpoints:");
    println!("  🔌 WebSocket: ws://127.0.0.1:3000/ws/{room_id}");
    println!("  📤 Send Message: POST /api/rooms/{room_id}/message");
    println!("  📊 Room Info: GET /api/rooms/{room_id}/info");
    println!("  📄 OpenAPI JSON: GET /api-docs/openapi.json");
    println!("  📖 Swagger UI: GET /api-docs");
    println!("  💚 Health Check: GET /health");
    println!("  🛡️ Rate Limit Test: GET /api/test-rate-limit");
    println!();
    println!("🚀 Server starting on http://127.0.0.1:3000");

    // Start the server
    app.run("127.0.0.1:3000").await?;

    Ok(())
}