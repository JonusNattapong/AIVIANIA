# AIVIANIA - Async-First Rust Web Framework

AIVIANIA is a type-safe, async-first web framework built on tokio and hyper. It provides routing, middleware support, JWT authentication, RBAC (Role-Based Access Control), WebSocket real-time communication, SQLite persistence, and a plugin system for extensibility, with a focus on enterprise-ready applications.

## Features

- **Async Routing**: Closure-based route handlers with type-safe parameters.
- **Middleware Stack**: Support for before/after request processing (logging, authentication, RBAC).
- **JWT Authentication**: Secure token-based auth with user registration and login.
- **Role-Based Access Control (RBAC)**: User roles and permissions with database-backed checks.
- **WebSocket Support**: Real-time bidirectional communication with broadcasting and subprotocol negotiation.
- **Database Integration**: SQLite with async operations, user management, and role assignment.
- **Response Helpers**: Easy JSON and HTML responses with builder pattern.
- **Plugin System**: Extensible for AI modules, databases, WebSockets, etc.
- **CLI Starter**: Run development server with `cargo run --example main`.

## Quick Start

1. Ensure Rust is installed (`https://rustup.rs/`).
2. Clone the repository: `git clone https://github.com/your-username/aiviania.git`
3. Run `cargo run --example main` to start the server on `http://127.0.0.1:3000`.

The example server includes:

- User registration at `POST /register`
- Login at `POST /login`
- Protected routes: `GET /admin/dashboard` (admin role), `GET /user/profile` (user role)
- WebSocket at `GET /ws` with broadcasting at `POST /broadcast`

## Example Usage

```rust
use aiviania::*;
use aiviania::middleware::{LoggingMiddleware, AuthMiddleware, RoleMiddleware};
use aiviania::auth::{AuthService, login_handler, register_handler};
use aiviania::database::Database;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize database and auth
    let db = Arc::new(Database::new().await?);
    let auth_service = Arc::new(AuthService::new("super-secret-key"));

    // Create router
    let mut router = Router::new();
    router.add_route(Route::new("POST", "/register", register_handler));
    router.add_route(Route::new("POST", "/login", login_handler));

    // Protected routes with RBAC
    router.add_route(Route::new("GET", "/admin/dashboard", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
        Response::new(StatusCode::OK).json(&serde_json::json!({
            "message": "Admin Dashboard",
            "data": "This is restricted to admin users only"
        }))
    }).with_middleware(Box::new(AuthMiddleware::new(auth_service.clone())))
      .with_middleware(Box::new(RoleMiddleware::new("admin", db.clone()))));

    // Create server
    let server = AivianiaServer::new(router)
        .with_middleware(Box::new(LoggingMiddleware));

    server.run("127.0.0.1:3000").await?;
    Ok(())
}
```

## Authentication & RBAC

### User Registration

```bash
curl -X POST http://127.0.0.1:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "securepass123"}'
```

### Login

```bash
curl -X POST http://127.0.0.1:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "securepass123"}'
# Returns: {"token": "jwt-token-here", "message": "Login successful", "user_id": 1}
```

### Protected Routes

Use the JWT token in Authorization header:

```bash
curl -H "Authorization: Bearer <jwt-token>" http://127.0.0.1:3000/user/profile
```

RBAC middleware checks user roles from the database and returns 403 Forbidden if insufficient permissions.

## WebSocket Usage

AIVIANIA supports WebSocket connections with subprotocol negotiation and compression:

```rust
// WebSocket upgrade route
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
    if let Some(ws_plugin) = plugins.get("websocket") {
        if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketPlugin>() {
            ws_handler.handler().broadcast("Hello, WebSocket clients!");
        }
    }
    Response::new(StatusCode::OK).json(&serde_json::json!({"status": "broadcasted"}))
}));
```

Connect via WebSocket client (e.g., websocat):

```bash
websocat ws://127.0.0.1:3000/ws
```

## Database Schema

AIVIANIA uses SQLite with the following tables:

- `users`: id, username, password_hash, created_at
- `roles`: id, name
- `user_roles`: user_id, role_id

Default roles: `admin`, `user`. New users get `user` role automatically.

## Modules

- `lib.rs`: Main library exports.
- `server.rs`: Server setup and lifecycle.
- `router.rs`: Routing logic and route matching.
- `request.rs`: Request wrapper utilities.
- `response.rs`: Response helpers (JSON, HTML).
- `middleware.rs`: Middleware traits and stack (Auth, RBAC, Logging).
- `auth.rs`: JWT authentication service and handlers.
- `database.rs`: SQLite database operations and user/role management.
- `websocket.rs`: WebSocket handler with upgrade, connections, and broadcasting.
- `plugin.rs`: Plugin system for extensions.

## Extending AIVIANIA

- Add new routes with `Route::new()`.
- Implement `Middleware` for custom processing.
- Implement `Plugin` for AI, DB, WebSocket, etc.
- For hot reload, use `cargo watch -x run --example main`.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Submit a pull request

## License

MIT
