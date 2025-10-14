//! Comprehensive example demonstrating WebSocket, Rate Limiting, and API Documentation features.
//!
//! This example shows:
//! - WebSocket real-time communication with rooms
//! - Rate limiting middleware
//! - OpenAPI/Swagger documentation generation
//! - Integration with authentication and GraphQL

use aiviania::*;
use aiviania::middleware::{LoggingMiddleware, RateLimitMiddleware, RateLimitBuilder, KeyStrategy};
use aiviania::plugin::{AIPlugin, PluginManager, WebSocketPlugin};
use aiviania::auth::{AuthService, AuthMiddleware, login_handler, register_handler};
use aiviania::database::{Database, DatabasePlugin};
use aiviania::graphql::{GraphQLService, GraphQLMiddleware};
use aiviania::email::{EmailService, EmailConfig};
use aiviania::oauth::{OAuthService, OAuthConfig, OAuthProvider};
use aiviania::upload::{UploadService, UploadConfig};
use aiviania::session::SessionManager;
use aiviania::rate_limit::RateLimitConfig;
use aiviania::openapi::OpenApiService;
use aiviania::websocket::WebSocketManager;
use hyper::{Request, Body, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize)]
struct ApiResponse {
    message: String,
    timestamp: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    websocket_connections: usize,
    graphql_enabled: bool,
    rate_limiting_enabled: bool,
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

    println!("🚀 Starting AIVIANIA Advanced Features Demo");
    println!("📊 WebSocket: ws://localhost:{}/ws", config.server_addr().split(':').nth(1).unwrap_or("3000"));
    println!("📚 API Docs: http://localhost:{}/swagger-ui/", config.server_addr());
    println!("🔒 Rate Limiting: 100 requests per minute per IP");
    println!("📧 Email: Configured with SMTP");
    println!("🔐 OAuth: Google/GitHub providers");
    println!("📤 File Upload: Enabled with validation");

    // Initialize services
    let auth_service = Arc::new(AuthService::new(&config.auth.jwt_secret));
    let db = Arc::new(Database::new().await?);
    let session_manager = Arc::new(SessionManager::new());

    // Initialize WebSocket plugin
    let websocket_plugin = Arc::new(WebSocketPlugin::new());
    let websocket_manager = websocket_plugin.manager();

    // Initialize GraphQL service
    let graphql_config = aiviania::graphql::GraphQLConfig::default();
    let graphql_service = Arc::new(GraphQLService::new(graphql_config));

    // Initialize Email service
    let email_config = EmailConfig {
        smtp_server: "smtp.gmail.com".to_string(),
        smtp_port: 587,
        smtp_username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
        smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
        from_email: "noreply@aiviania.com".to_string(),
        from_name: "AIVIANIA".to_string(),
    };
    let email_service = Arc::new(EmailService::new(email_config));

    // Initialize OAuth service
    let oauth_config = OAuthConfig {
        providers: vec![
            OAuthProvider {
                name: "google".to_string(),
                client_id: std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
                client_secret: std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
                auth_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                redirect_url: "http://localhost:3000/auth/google/callback".to_string(),
                scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            },
        ],
    };
    let oauth_service = Arc::new(OAuthService::new(oauth_config));

    // Initialize Upload service
    let upload_config = UploadConfig {
        max_file_size: 10 * 1024 * 1024, // 10MB
        allowed_extensions: vec!["jpg".to_string(), "png".to_string(), "pdf".to_string()],
        upload_dir: "uploads".to_string(),
    };
    let upload_service = Arc::new(UploadService::new(upload_config));

    // Initialize OpenAPI service
    let openapi_service = Arc::new(OpenApiService::new());

    // Create router
    let mut router = Router::new();

    // Rate limiting middleware (100 requests per minute per IP)
    let rate_limit_middleware = RateLimitBuilder::new()
        .requests_per_window(100)
        .window_duration(Duration::from_secs(60))
        .key_strategy(KeyStrategy::IP)
        .build();

    // Add global middleware
    router.add_middleware(Box::new(LoggingMiddleware));
    router.add_middleware(Box::new(rate_limit_middleware));

    // Health check endpoint
    router.add_route(Route::new("GET", "/health", move |_req: Request<Body>, plugins: Arc<PluginManager>| async move {
        let ws_connections = if let Some(ws_plugin) = plugins.get("websocket") {
            if let Some(ws) = ws_plugin.as_any().downcast_ref::<WebSocketPlugin>() {
                ws.manager().connection_count().await
            } else {
                0
            }
        } else {
            0
        };

        Response::new(StatusCode::OK).json(&HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            websocket_connections: ws_connections,
            graphql_enabled: true,
            rate_limiting_enabled: true,
        })
    }));

    // API Documentation endpoints
    let openapi_service_clone = Arc::clone(&openapi_service);
    router.add_route(Route::new("GET", "/api-docs/openapi.json", move |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        match openapi_service_clone.generate_openapi_json() {
            Ok(json) => Response::new(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(json)),
            Err(_) => Response::new(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to generate OpenAPI documentation")),
        }
    }));

    let openapi_service_clone = Arc::clone(&openapi_service);
    router.add_route(Route::new("GET", "/swagger-ui/", move |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        Response::new(StatusCode::OK)
            .header("content-type", "text/html")
            .body(Body::from(openapi_service_clone.serve_swagger_ui()))
    }));

    // WebSocket endpoint
    let websocket_plugin_clone = Arc::clone(&websocket_plugin);
    router.add_route(Route::new("GET", "/ws", move |req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // Extract user ID from session (simplified)
        let user_id = req.headers()
            .get("x-user-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        match websocket_plugin_clone.handle_upgrade(req, user_id).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("WebSocket upgrade failed: {:?}", e);
                Response::new(StatusCode::BAD_REQUEST)
                    .body(Body::from("WebSocket upgrade failed"))
            }
        }
    }));

    // GraphQL endpoint
    let graphql_service_clone = Arc::clone(&graphql_service);
    router.add_route(Route::new("GET", "/graphql", move |req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // For GET requests, serve GraphQL playground
        if cfg!(feature = "utoipa") {
            Response::new(StatusCode::OK)
                .header("content-type", "text/html")
                .body(Body::from(include_str!("../templates/graphql_playground.html")))
        } else {
            Response::new(StatusCode::OK)
                .json(&serde_json::json!({"message": "GraphQL playground not available"}))
        }
    }));

    let graphql_service_clone = Arc::clone(&graphql_service);
    router.add_route(Route::new("POST", "/graphql", move |req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // Parse GraphQL request from body
        // This is a simplified implementation - in production you'd parse the JSON body
        let response = serde_json::json!({
            "data": {
                "message": "GraphQL endpoint active",
                "features": ["queries", "mutations", "subscriptions"]
            }
        });

        Response::new(StatusCode::OK).json(&response)
    }).with_middleware(Box::new(GraphQLMiddleware::new(
        Arc::clone(&session_manager),
        Arc::clone(&db)
    ))));

    // Authentication endpoints
    router.add_route(Route::new("POST", "/auth/login", login_handler));
    router.add_route(Route::new("POST", "/auth/register", register_handler));

    // OAuth endpoints
    let oauth_service_clone = Arc::clone(&oauth_service);
    router.add_route(Route::new("GET", "/auth/google", move |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // Redirect to Google OAuth
        Response::new(StatusCode::FOUND)
            .header("location", "https://accounts.google.com/o/oauth2/auth?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/auth/google/callback&scope=openid%20email%20profile&response_type=code")
            .body(Body::empty())
    }));

    // File upload endpoint
    let upload_service_clone = Arc::clone(&upload_service);
    router.add_route(Route::new("POST", "/upload", move |mut req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        match upload_service_clone.handle_upload(&mut req).await {
            Ok(result) => Response::new(StatusCode::OK).json(&result),
            Err(e) => Response::new(StatusCode::BAD_REQUEST).json(&serde_json::json!({
                "error": "Upload failed",
                "message": e.to_string()
            })),
        }
    }));

    // Demo endpoint with rate limiting
    router.add_route(Route::new("GET", "/api/demo", |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        Response::new(StatusCode::OK).json(&ApiResponse {
            message: "This endpoint is rate limited to 100 requests per minute per IP".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }));

    // WebSocket room management demo
    router.add_route(Route::new("POST", "/api/broadcast", move |req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // Broadcast message to all WebSocket connections
        let message = serde_json::json!({
            "type": "broadcast",
            "message": "Server broadcast message",
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        match websocket_manager.broadcast(&message.to_string()).await {
            Ok(_) => {
                let connection_count = websocket_manager.connection_count().await;
                Response::new(StatusCode::OK).json(&serde_json::json!({
                    "status": "broadcasted",
                    "connections": connection_count
                }))
            },
            Err(e) => Response::new(StatusCode::INTERNAL_SERVER_ERROR).json(&serde_json::json!({
                "error": "Broadcast failed",
                "message": e.to_string()
            })),
        }
    }));

    // Email demo endpoint
    let email_service_clone = Arc::clone(&email_service);
    router.add_route(Route::new("POST", "/api/send-email", move |req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // This would parse email details from request body
        // For demo purposes, we'll just show the capability
        Response::new(StatusCode::OK).json(&serde_json::json!({
            "status": "Email service configured",
            "features": ["SMTP", "Templates", "Verification", "Password Reset"],
            "note": "Configure SMTP_USERNAME and SMTP_PASSWORD environment variables"
        }))
    }));

    // Initialize plugins
    let mut plugin_manager = PluginManager::new();
    plugin_manager.register(Box::new(DatabasePlugin::new(Arc::clone(&db))));
    plugin_manager.register(Box::new(websocket_plugin));
    plugin_manager.register(Box::new(AIPlugin::new()));

    // Create and start server
    let server = Server::new(config, router, plugin_manager);

    println!("\n📋 Available endpoints:");
    println!("  GET  /health              - Health check with stats");
    println!("  GET  /api-docs/openapi.json - OpenAPI specification");
    println!("  GET  /swagger-ui/         - Swagger UI documentation");
    println!("  GET  /ws                  - WebSocket connection");
    println!("  GET  /graphql             - GraphQL playground");
    println!("  POST /graphql             - GraphQL API");
    println!("  POST /auth/login          - User login");
    println!("  POST /auth/register       - User registration");
    println!("  GET  /auth/google         - Google OAuth");
    println!("  POST /upload              - File upload");
    println!("  GET  /api/demo            - Rate limited demo endpoint");
    println!("  POST /api/broadcast       - Broadcast to WebSocket clients");
    println!("  POST /api/send-email      - Email service demo");
    println!("\n🎯 WebSocket Message Format:");
    println!("  {{\"type\": \"join\", \"room\": \"room_name\"}}");
    println!("  {{\"type\": \"leave\", \"room\": \"room_name\"}}");
    println!("  {{\"type\": \"room_message\", \"room\": \"room_name\", \"message\": \"Hello!\"}}");
    println!("  {{\"type\": \"private_message\", \"user_id\": \"user123\", \"message\": \"Hi!\"}}");
    println!("  {{\"type\": \"broadcast\", \"message\": \"Global message\"}}");

    server.start().await?;

    Ok(())
}