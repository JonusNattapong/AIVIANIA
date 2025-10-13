# AIVIANIA - Minimal Async Rust Web Framework

AIVIANIA is a type-safe, async-first web framework built on tokio and hyper. It provides routing with macros, middleware support, response helpers, and a plugin system for extensibility, with a focus on AI-ready applications.

## Features

- **Async Routing**: Closure-based route handlers with type-safe parameters.
- **Middleware**: Support for before/after request processing (logging, authentication).
- **Authentication**: JWT-based auth with token generation and validation.
- **WebSocket Support**: Real-time bidirectional communication with broadcasting.
- **AI Integration**: OpenAI API integration for LLM calls.
- **Database**: SQLite integration with async operations and user management.
- **Response Helpers**: Easy JSON and HTML responses with builder pattern.
- **Plugin System**: Extensible for AI modules, databases, etc.
- **CLI Starter**: Run development server with `cargo run --example main`.

## Quick Start

1. Ensure Rust is installed (https://rustup.rs/).
2. Clone or copy the project structure.
3. Run `cargo run --example main` to start the server on http://127.0.0.1:3000.

## Example Usage

```rust
use aiviania::*;
use aiviania::middleware::LoggingMiddleware;
use aiviania::plugin::AIPlugin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:3000".parse()?;
    let server = Server::new(addr)
        .middleware(Box::new(LoggingMiddleware))
        .plugin(Box::new(AIPlugin::new("your-openai-api-key".to_string())))
        .route(get!("/", hello_handler));

    server.run().await
}

async fn hello_handler(_req: Request<Body>, plugins: &PluginManager) -> Response {
    let ai_plugin = plugins.get("ai").unwrap().downcast_ref::<AIPlugin>().unwrap();
    let ai_response = ai_plugin.call_ai("Hello!").await.unwrap();

    Response::new(StatusCode::OK).json(&serde_json::json!({
        "message": "Hello from AIVIANIA!",
        "ai": ai_response
    }))
}
```

## WebSocket Usage

AIVIANIA supports WebSocket connections for real-time communication:

```rust
// In your route handler
router.add_route(Route::new("GET", "/ws", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    if let Some(ws_plugin) = plugins.get("websocket") {
        if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketPlugin>() {
            match ws_handler.handler().handle_upgrade(req).await {
                Ok(response) => return response,
                Err(_) => return Response::new(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
    Response::new(StatusCode::INTERNAL_SERVER_ERROR)
}));

// Broadcast to all connected clients
router.add_route(Route::new("POST", "/broadcast", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    // Parse message and broadcast
    ws_handler.broadcast("Hello, WebSocket clients!");
    Response::new(StatusCode::OK).json(&serde_json::json!({"status": "broadcasted"}))
}));
```

## Authentication

AIVIANIA includes JWT-based authentication:

```rust
use aiviania::auth::{AuthService, AuthMiddleware, login_handler};

// Create auth service
let auth_service = Arc::new(AuthService::new("your-secret-key"));

// Add to server
let server = AivianiaServer::new(router)
    .with_middleware(Box::new(AuthMiddleware::new(auth_service)))
    .route(Route::new("POST", "/login", login_handler));

// Login with POST /login {"username": "admin", "password": "password"}
// Returns JWT token for authenticated requests
```

Protected routes check `Authorization: Bearer <token>` headers.

## Modules

- `lib.rs`: Main library exports and macros.
- `server.rs`: Server setup and lifecycle.
- `router.rs`: Routing logic and route matching.
- `request.rs`: Request wrapper utilities.
- `response.rs`: Response helpers (JSON, HTML).
- `middleware.rs`: Middleware traits and stack.
- `plugin.rs`: Plugin system for extensions.

## Extending AIVIANIA

- Add new routes with `get!`, `post!`, etc.
- Implement `Middleware` for custom processing.
- Implement `Plugin` for AI, DB, etc.
- For hot reload, integrate with `cargo-watch` or similar.

## License

MIT