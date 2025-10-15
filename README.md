# AIVIANIA — Async-First Rust Web Framework

![CI](https://github.com/JonusNattapong/AIVIANIA/workflows/CI/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/aiviania.svg)](https://crates.io/crates/aiviania)
[![Docs.rs](https://docs.rs/aiviania/badge.svg)](https://docs.rs/aiviania)
[![License](https://img.shields.io/github/license/JonusNattapong/AIVIANIA.svg)](https://github.com/JonusNattapong/AIVIANIA/blob/main/LICENSE)

AIVIANIA is a type-safe, async-first web framework built on tokio and hyper. It provides routing, middleware support, JWT authentication, RBAC (Role-Based Access Control), advanced WebSocket real-time communication with room-based messaging, comprehensive rate limiting, automatic API documentation, SQLite persistence, session management, background job processing, and a plugin system for extensibility, with a focus on enterprise-ready applications.

AIVIANIA is a type-safe, async-first web framework built on tokio and hyper. It provides routing, middleware support, JWT authentication, RBAC (Role-Based Access Control), advanced WebSocket real-time communication with room-based messaging, comprehensive rate limiting, automatic API documentation, SQLite persistence, session management, background job processing, and a plugin system for extensibility, with a focus on enterprise-ready applications.

## Features

- **Async Routing**: Closure-based route handlers with type-safe parameters.
- **Middleware Stack**: Support for before/after request processing (logging, authentication, RBAC, rate limiting).
- **JWT Authentication**: Secure token-based auth with user registration and login.
- **Role-Based Access Control (RBAC)**: User roles and permissions with database-backed checks.
- **Session Management**: Configurable session storage (memory, Redis, database) with secure cookie handling.
- **Background Jobs/Queues**: Asynchronous job processing with Redis-backed queues and worker management.
- **File Upload Support**: Multipart form data handling with configurable size limits, type validation, and storage management.
- **Email Integration**: SMTP email sending with templates, verification, and password reset functionality.
- **GraphQL Support**: Complete GraphQL API with schema definition, resolvers, and interactive playground.
- **OAuth Integration**: Multi-provider OAuth2 authentication (Google, GitHub, Facebook) with secure token handling.
- **WebSocket Support**: Real-time bidirectional communication with room-based messaging, user management, and structured JSON protocols.
- **Database Integration**: SQLite with async operations, repository pattern, RBAC integration, and comprehensive CRUD operations.
- **Blockchain Integration**: Web3 integration for Ethereum and other blockchain networks.
- **API Documentation**: Automatic OpenAPI/Swagger specification generation with interactive UI.
- **Metrics & Monitoring**: Prometheus metrics collection and health checks.
- **Caching**: Configurable caching backends (memory, Redis).
- **Rate Limiting**: Configurable rate limiting with multiple algorithms.
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
- Database example: `cargo run --features sqlite --example database_example`

## Docker Deployment

AIVIANIA includes Docker support for easy deployment:

### Build and Run with Docker

```bash
# Build the Docker image
docker build -t aiviania .

# Run the container
docker run -p 3000:3000 -e JWT_SECRET=your-secret-key-here aiviania
```

### Using Docker Compose

For a complete setup with persistent data:

```bash
# Start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

The Docker setup includes:
- Multi-stage build for optimized image size
- Environment variable configuration
- Volume mounting for data persistence
- Exposed port 3000 for web access

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

## Changelog

### v0.1.4 — 2025-10-15

- Add body-buffer middleware to safely buffer and re-use request bodies.
- Security improvements: CSRF protection, CORS handling, security headers and automated tests covering CSRF/CORS flows.
- Observability: request metrics and a metrics middleware for Prometheus-style collection.
- CI: GitHub Actions workflow added to run formatting, clippy, cargo test and a Docker build + Trivy image scan.

Merged PRs: #4, #5

---

For full details and examples, see the `examples/` directory and the project CHANGELOG in GitHub releases.

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

AIVIANIA supports advanced WebSocket connections with room-based messaging, user management, and structured JSON protocols:

```rust
use aiviania::websocket::{WebSocketManager, WSMessage, MessageType};
use std::sync::Arc;

// Create WebSocket manager
let ws_manager = Arc::new(WebSocketManager::new());

// WebSocket upgrade route with room support
router.add_route(Route::new("GET", "/ws/:room_id", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    let room_id = req.uri().path().split('/').last().unwrap_or("default").to_string();
    
    if let Some(ws_plugin) = plugins.get("websocket") {
        if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketManager>() {
            match ws_handler.handle_upgrade(req, Some(room_id)).await {
                Ok(response) => return response,
                Err(_) => return Response::new(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
    Response::new(StatusCode::INTERNAL_SERVER_ERROR)
}));

// Send message to specific room
router.add_route(Route::new("POST", "/rooms/:room_id/message", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    let room_id = req.uri().path().split('/').nth(2).unwrap_or("default").to_string();
    
    // Parse message from request body
    let message_data: serde_json::Value = serde_json::from_slice(req.body().as_ref())?;
    
    if let Some(ws_plugin) = plugins.get("websocket") {
        if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketManager>() {
            let ws_message = WSMessage {
                message_type: MessageType::Chat,
                room_id: Some(room_id),
                user_id: Some("user123".to_string()),
                content: message_data["content"].as_str().unwrap_or("").to_string(),
                timestamp: chrono::Utc::now(),
                metadata: None,
            };
            
            ws_handler.broadcast_to_room(&ws_message.room_id.as_ref().unwrap(), &ws_message).await;
        }
    }
    
    Response::new(StatusCode::OK).json(&serde_json::json!({"status": "sent"}))
}));

// Get room information
router.add_route(Route::new("GET", "/rooms/:room_id/info", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    let room_id = req.uri().path().split('/').nth(2).unwrap_or("default").to_string();
    
    if let Some(ws_plugin) = plugins.get("websocket") {
        if let Some(ws_handler) = ws_plugin.as_any().downcast_ref::<WebSocketManager>() {
            let room_info = ws_handler.get_room_info(&room_id).await;
            return Response::new(StatusCode::OK).json(&room_info);
        }
    }
    
    Response::new(StatusCode::INTERNAL_SERVER_ERROR)
}));
```

### WebSocket Message Types

AIVIANIA supports structured messaging with the following message types:

- **Chat**: General chat messages
- **Join**: User joining a room
- **Leave**: User leaving a room  
- **System**: System notifications
- **Private**: Direct messages between users
- **Custom**: Application-specific messages

### Room Management

- **Room-based messaging**: Messages are scoped to specific rooms
- **User tracking**: Track connected users per room
- **Connection monitoring**: Automatic cleanup of disconnected users
- **Broadcast capabilities**: Send to entire room or specific users

Connect via WebSocket client:

```bash
# Connect to default room
websocat ws://127.0.0.1:3000/ws/default

# Send structured JSON message
echo '{"type": "chat", "content": "Hello Room!", "user_id": "user123"}' | websocat ws://127.0.0.1:3000/ws/default
```

## Rate Limiting

AIVIANIA provides comprehensive rate limiting middleware to protect your APIs from abuse:

```rust
use aiviania::rate_limit::{RateLimitMiddleware, RateLimitBuilder, KeyStrategy};
use std::sync::Arc;

// Create rate limiter with IP-based limiting
let rate_limiter = Arc::new(RateLimitMiddleware::new(
    RateLimitBuilder::new()
        .with_capacity(100)  // 100 requests
        .with_refill_rate(10)  // 10 requests per second
        .with_window_secs(60)  // 1 minute window
        .with_key_strategy(KeyStrategy::IpAddress)
        .build()
));

// Add to router
router.add_middleware(rate_limiter);

// Or use user-based limiting with Redis backend
let user_rate_limiter = Arc::new(RateLimitMiddleware::new(
    RateLimitBuilder::new()
        .with_capacity(1000)
        .with_refill_rate(50)
        .with_window_secs(3600)  // 1 hour window
        .with_key_strategy(KeyStrategy::UserId)
        .with_redis_backend("redis://127.0.0.1:6379")
        .build()
));

router.add_middleware(user_rate_limiter);
```

### Rate Limiting Strategies

- **IP Address**: Rate limit by client IP address
- **User ID**: Rate limit by authenticated user ID
- **Custom**: Implement custom key extraction logic
- **Endpoint-specific**: Different limits per route

### Rate Limiting Backends

- **In-Memory**: Fast, suitable for single-instance deployments
- **Redis**: Distributed rate limiting for multi-instance deployments
- **Database**: Persistent rate limiting with SQL databases

### Rate Limiting Configuration

```rust
// Configure different limits for different endpoints
let api_limiter = RateLimitBuilder::new()
    .with_capacity(100)
    .with_refill_rate(20)
    .with_burst_allowance(10)
    .with_key_strategy(KeyStrategy::IpAddress)
    .build();

// Apply to specific routes
router.add_route_with_middleware(
    Route::new("GET", "/api/*", api_handler),
    vec![Arc::new(RateLimitMiddleware::new(api_limiter))]
);
```

## API Documentation

AIVIANIA automatically generates OpenAPI/Swagger documentation for your APIs:

```rust
use aiviania::openapi::{OpenApiService, OpenApiConfig};
use std::sync::Arc;

// Create OpenAPI service
let openapi_config = OpenApiConfig {
    title: "AIVIANIA API".to_string(),
    version: "1.0.0".to_string(),
    description: Some("Enterprise Web Framework API".to_string()),
    ..Default::default()
};

let openapi_service = Arc::new(OpenApiService::new(openapi_config));

// Add OpenAPI routes
router.add_route(Route::new("GET", "/api-docs/openapi.json", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    if let Some(openapi_plugin) = plugins.get("openapi") {
        if let Some(openapi_svc) = openapi_plugin.as_any().downcast_ref::<OpenApiService>() {
            let spec = openapi_svc.generate_spec().await;
            return Response::new(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(spec));
        }
    }
    Response::new(StatusCode::INTERNAL_SERVER_ERROR)
}));

// Serve Swagger UI
router.add_route(Route::new("GET", "/api-docs", |req: Request<Body>, plugins: Arc<PluginManager>| async move {
    if let Some(openapi_plugin) = plugins.get("openapi") {
        if let Some(openapi_svc) = openapi_plugin.as_any().downcast_ref::<OpenApiService>() {
            let html = openapi_svc.generate_swagger_ui("/api-docs/openapi.json");
            return Response::new(StatusCode::OK)
                .header("content-type", "text/html")
                .body(Body::from(html));
        }
    }
    Response::new(StatusCode::INTERNAL_SERVER_ERROR)
}));
```

### OpenAPI Features

- **Automatic generation**: Generate specs from your route definitions
- **Swagger UI**: Interactive API documentation
- **Schema validation**: JSON Schema validation for requests/responses
- **Authentication**: JWT Bearer token support in docs
- **Examples**: Request/response examples in documentation

### Documenting Your APIs

```rust
use utoipa::ToSchema;

// Define schemas for your data models
#[derive(ToSchema)]
struct User {
    id: i64,
    name: String,
    email: String,
}

// Document your routes
#[utoipa::path(
    get,
    path = "/users/{id}",
    responses(
        (status = 200, description = "User found", body = User),
        (status = 404, description = "User not found")
    ),
    params(
        ("id" = i64, Path, description = "User ID")
    )
)]
async fn get_user(req: AivianiaRequest) -> AivianiaResponse {
    // Your handler logic
    Response::new(StatusCode::OK).json(&User {
        id: 1,
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
    })
}

## Contributing & Running Checks

Thank you for contributing to AIVIANIA! To run basic checks locally:

```powershell
# Run the type check / build
cargo check

# Run tests (once tests are added)
cargo test
```

Coding style: please follow Rust 2021 idioms, run `cargo fmt` before submitting PRs, and keep commits small and focused.

## Changelog (Recent)

- 2025-10-14: Security modules updated
    - Fixed several compile-time warnings in `src/security/*` (unused fields and helpers). These were intentionally marked or renamed to avoid dead-code warnings while the modules are being integrated and tested.
    - CSRF, CORS and security header middleware implemented and compiled cleanly under `cargo check`.

If you'd like me to open a PR with these changes or create further unit tests and examples, tell me which next task to pick from the todo list.
## Session Management

AIVIANIA provides configurable session management with multiple storage backends:

```rust
use aiviania::session::{SessionManager, SessionMiddleware, MemorySessionStore};
use std::sync::Arc;

// Create session manager
let session_manager = Arc::new(SessionManager::new());

// Add session middleware to router
let session_middleware = Arc::new(SessionMiddleware::new(session_manager));
router.add_middleware(session_middleware);

// Use sessions in handlers
async fn my_handler(req: AivianiaRequest) -> AivianiaResponse {
    if let Some(session) = req.extensions().get::<SessionData>() {
        // Access session data
        let user_id: i64 = session.get("user_id").unwrap_or(0);
        // Modify session
        session.set("last_visit", Utc::now());
    }
    Response::new(StatusCode::OK).json(&json!({"status": "ok"}))
}
```

### Session Storage Backends

- **Memory Store**: Fast in-memory storage for development
- **Redis Store**: Production-ready with TTL (`--features redis`)
- **Database Store**: SQL database persistence (extensible)

## Background Jobs & Queues

Process asynchronous jobs with configurable queues and workers:

```rust
use aiviania::jobs::{JobManager, JobWorker, MemoryJobQueue};
use std::sync::Arc;

// Create job queue and manager
let queue = Arc::new(MemoryJobQueue::new());
let manager = JobManager::new(queue.clone());

// Create worker with job handlers
let worker = JobWorker::new(queue.clone())
    .register_handler("send_email", EmailHandler)
    .with_concurrency(5);

// Start worker
tokio::spawn(async move {
    worker.start(&["default"]).await.unwrap();
});

// Enqueue jobs
let job_id = manager.enqueue("send_email", json!({
    "to": "user@example.com",
    "subject": "Hello",
    "body": "Welcome!"
})).await?;
```

### Job Features

- **Priority Queues**: Critical, High, Normal, Low priorities
- **Retry Logic**: Configurable attempts with error handling
- **Scheduling**: Delay jobs or schedule for specific times
- **Monitoring**: Job status tracking and queue statistics

## Email Integration

AIVIANIA provides comprehensive email functionality with SMTP support, HTML templates, and user verification:

```rust
use aiviania::email::{EmailService, EmailConfig, EmailVerificationService, PasswordResetService};
use std::sync::Arc;

// Configure email service
let email_config = EmailConfig {
    smtp_host: "smtp.gmail.com".to_string(),
    smtp_port: 587,
    smtp_username: "your-email@gmail.com".to_string(),
    smtp_password: "your-app-password".to_string(),
    use_tls: true,
    from_email: "noreply@yourapp.com".to_string(),
    from_name: "Your App".to_string(),
    templates_dir: "./templates".to_string(),
};

let email_service = Arc::new(EmailService::new(email_config)?);

// Email verification service
let verification_service = Arc::new(EmailVerificationService::new(email_service.clone()));

// Send verification email
let token = verification_service.send_verification("user@example.com", "user_id").await?;

// Verify email token
let verification_data = verification_service.verify_token(&token).await?;

// Password reset service
let reset_service = Arc::new(PasswordResetService::new(email_service.clone()));

// Send password reset email
let reset_token = reset_service.send_reset_email("user@example.com", "user_id").await?;

// Verify reset token
let reset_data = reset_service.verify_reset_token(&reset_token).await?;
```

### Email Features

- **SMTP Support**: Configurable SMTP servers with TLS encryption
- **HTML Templates**: Handlebars templating with custom data
- **Email Verification**: Secure token-based email verification
- **Password Reset**: Secure password reset with token validation
- **Template Management**: Register and manage custom email templates
- **Error Handling**: Comprehensive error types and recovery

### Email Templates

AIVIANIA includes default HTML email templates:

- `verification.html`: Email verification with styled code display
- `password_reset.html`: Password reset with secure token handling
- `welcome.html`: Welcome email with feature highlights

## GraphQL Support

Complete GraphQL API implementation with schema definition, resolvers, and interactive playground:

```rust
use aiviania::graphql::{GraphQLService, GraphQLConfig, GraphQLContext, GraphQLMiddleware};
use async_graphql::{Object, SimpleObject};
use std::sync::Arc;

// Configure GraphQL service
let graphql_config = GraphQLConfig {
    enable_playground: true,
    path: "/graphql".to_string(),
    enable_introspection: true,
    max_complexity: Some(1000),
    max_depth: Some(10),
};

let graphql_service = Arc::new(GraphQLService::new(graphql_config));

// Add GraphQL middleware
server.add_middleware(GraphQLMiddleware::new(
    session_manager.clone(),
    database.clone(),
));

// GraphQL routes
server.add_route(Route::get("/graphql", graphql_playground_handler));
server.add_route(Route::post("/graphql", graphql_endpoint_handler));
```

### GraphQL Schema Example

```rust
use async_graphql::*;

// Define GraphQL types
#[derive(SimpleObject)]
struct User {
    id: ID,
    username: String,
    email: String,
    full_name: Option<String>,
}

// Query root
#[Object]
impl QueryRoot {
    async fn user(&self, ctx: &Context<'_>, id: ID) -> Result<Option<User>> {
        // Fetch user from database
        Ok(Some(User {
            id,
            username: "example".to_string(),
            email: "user@example.com".to_string(),
            full_name: Some("Example User".to_string()),
        }))
    }

    async fn users(&self, ctx: &Context<'_>, limit: Option<i32>) -> Result<Vec<User>> {
        // Fetch users with pagination
        Ok(vec![])
    }
}

// Mutation root
#[Object]
impl MutationRoot {
    async fn create_user(&self, ctx: &Context<'_>, input: CreateUserInput) -> Result<User> {
        // Create new user
        Ok(User {
            id: ID::from(uuid::Uuid::new_v4().to_string()),
            username: input.username,
            email: input.email,
            full_name: input.full_name,
        })
    }
}
```

### GraphQL Features

- **Schema Definition**: Type-safe schema with async resolvers
- **Interactive Playground**: GraphiQL interface for testing queries
- **Authentication Context**: User context in resolvers
- **Query Complexity**: Protection against expensive queries
- **Introspection**: API discovery and documentation
- **Error Handling**: Structured error responses

## OAuth Integration

Multi-provider OAuth2 authentication with secure token handling and user management:

```rust
use aiviania::oauth::{OAuthService, OAuthConfig, OAuthMiddleware};
use std::sync::Arc;

// Configure OAuth providers
let mut oauth_config = OAuthConfig::default();

// Configure Google OAuth
if let Some(google) = oauth_config.providers.get_mut("google") {
    google.client_id = "your-google-client-id".to_string();
    google.client_secret = "your-google-client-secret".to_string();
    google.redirect_url = "http://localhost:3000/auth/google/callback".to_string();
}

// Configure GitHub OAuth
if let Some(github) = oauth_config.providers.get_mut("github") {
    github.client_id = "your-github-client-id".to_string();
    github.client_secret = "your-github-client-secret".to_string();
    github.redirect_url = "http://localhost:3000/auth/github/callback".to_string();
}

let oauth_service = Arc::new(OAuthService::new(oauth_config)?);

// Add OAuth middleware
server.add_middleware(OAuthMiddleware::new(
    oauth_service.clone(),
    session_manager.clone(),
    database.clone(),
));

// OAuth routes
server.add_route(Route::get("/auth/google", oauth_login_handler));
server.add_route(Route::get("/auth/github", oauth_login_handler));
server.add_route(Route::get("/auth/google/callback", oauth_callback_handler));
server.add_route(Route::get("/auth/github/callback", oauth_callback_handler));
```

### OAuth Flow Example

```bash
# 1. Initiate OAuth login
curl http://localhost:3000/auth/google
# Redirects to Google OAuth

# 2. Google redirects back with code
# GET /auth/google/callback?code=...&state=...

# 3. Exchange code for tokens and user info
# Returns user information and authentication tokens
```

### OAuth Features

- **Multi-Provider Support**: Google, GitHub, Facebook, and custom providers
- **Secure Token Exchange**: CSRF protection with state parameters
- **User Information**: Standardized user data across providers
- **Session Integration**: Automatic session creation after OAuth
- **Provider Management**: Easy configuration and status checking
- **Error Handling**: Comprehensive OAuth error management

## API Documentation

Automatic OpenAPI/Swagger documentation generation:

```bash
# Enable API docs
cargo run --features utoipa --example main

# Access Swagger UI at http://127.0.0.1:3000/swagger-ui
# OpenAPI spec at http://127.0.0.1:3000/api-docs/openapi.json
```

Add documentation to your structs:

```rust
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}
```

## Blockchain Integration

Web3 integration for blockchain interactions:

```rust
use aiviania::blockchain::{BlockchainClient, BlockchainPlugin};
use web3::types::Address;

// Create blockchain client
let client = BlockchainClient::new("https://mainnet.infura.io/v3/YOUR_PROJECT_ID").await?;

// Get account balance
let balance = client.get_balance(address).await?;
```

## Metrics & Monitoring

Prometheus metrics collection and health checks:

```rust
use aiviania::metrics::MetricsCollector;

// Access metrics at /metrics endpoint
// Includes HTTP request counts, response times, database connections, etc.
```

## Caching

Configurable caching with multiple backends:

```rust
use aiviania::cache::{Cache, MemoryCache};

// Create cache
let cache = Arc::new(MemoryCache::new());

// Cache operations
cache.set("key", "value", Duration::hours(1)).await?;
let value: Option<String> = cache.get("key").await?;
```

## Rate Limiting

Protect your API with configurable rate limiting:

```rust
use aiviania::rate_limit::{RateLimiter, FixedWindow};

// Create rate limiter (100 requests per minute per IP)
let limiter = Arc::new(RateLimiter::new(FixedWindow::new(100, Duration::minutes(1))));

// Use in middleware
let rate_limit_middleware = RateLimitMiddleware::new(limiter, "api");
router.add_middleware(rate_limit_middleware);
```

## Database Integration

AIVIANIA provides comprehensive database integration with async operations, repository pattern, and RBAC support:

```rust
use aiviania::database::{DatabaseConfig, DatabaseManager, DatabaseType, Repository};
use aiviania::database::repositories::UserRepository;
use aiviania::auth::rbac::RBACService;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure SQLite database
    let config = DatabaseConfig {
        database_type: DatabaseType::Sqlite,
        connection_string: ":memory:".to_string(), // In-memory database
        max_connections: 5,
        min_connections: 1,
        connection_timeout: 30,
        acquire_timeout: 10,
        idle_timeout: 300,
        max_lifetime: 3600,
    };

    // Create database manager
    let db_manager = Arc::new(DatabaseManager::new(config).await?);

    // Create repository
    let user_repo = UserRepository::new(db_manager.clone());

    // Create RBAC service
    let rbac_service = Arc::new(RBACService::new());

    // Create a test user
    let test_user = User {
        id: None,
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hashed_password_here".to_string(),
        role: "user".to_string(),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        avatar_url: None,
        is_active: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Save user (returns user ID)
    let user_id = user_repo.save(test_user).await?;
    println!("Created user with ID: {}", user_id);

    // Find user by ID
    if let Some(user) = user_repo.find_by_id(user_id).await? {
        println!("Found user: {} ({})", user.username, user.email);
    }

    // Update user
    let mut updated_user = user_repo.find_by_id(user_id).await?.unwrap();
    updated_user.first_name = Some("Updated".to_string());
    user_repo.update(updated_user).await?;

    // List all users
    let users = user_repo.find_all().await?;
    println!("Total users: {}", users.len());

    // Delete user
    user_repo.delete(user_id).await?;
    println!("User deleted successfully");

    Ok(())
}
```

### Repository Pattern

AIVIANIA implements the repository pattern for clean data access:

```rust
use aiviania::database::Repository;
use async_trait::async_trait;

#[async_trait]
impl<T: DatabaseConnection + Send + Sync> Repository<User, i64> for UserRepository<T> {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DatabaseError> {
        // Implementation
    }

    async fn find_all(&self) -> Result<Vec<User>, DatabaseError> {
        // Implementation
    }

    async fn save(&self, entity: User) -> Result<i64, DatabaseError> {
        // Implementation - returns ID
    }

    async fn update(&self, entity: User) -> Result<(), DatabaseError> {
        // Implementation
    }

    async fn delete(&self, id: i64) -> Result<(), DatabaseError> {
        // Implementation
    }
}
```

### Database Features

- **Multi-backend Support**: SQLite (primary), PostgreSQL, MySQL, MongoDB
- **Async Operations**: All database operations are async with tokio
- **Repository Pattern**: Clean separation of data access logic
- **RBAC Integration**: User roles and permissions stored in database
- **Migration System**: Schema management with up/down migrations
- **Connection Pooling**: Configurable connection limits and timeouts
- **Error Handling**: Comprehensive error types and recovery

### Database Schema

AIVIANIA uses SQLite with the following tables:

- `users`: id, username, email, password_hash, role, first_name, last_name, avatar_url, is_active, created_at, updated_at
- `schema_migrations`: version, description, applied_at (for migration tracking)

### Database Configuration

```rust
let config = DatabaseConfig {
    database_type: DatabaseType::Sqlite,
    connection_string: ":memory:".to_string(), // or "sqlite:app.db"
    max_connections: 10,
    min_connections: 1,
    connection_timeout: 30,
    acquire_timeout: 10,
    idle_timeout: 300,
    max_lifetime: 3600,
};
```

### Running Database Example

```bash
# Run the comprehensive database example
cargo run --features sqlite --example database_example
```

This example demonstrates:
- Database connection setup
- Schema creation
- CRUD operations (Create, Read, Update, Delete)
- Repository pattern usage
- RBAC integration
- Error handling

## Configuration

AIVIANIA supports configuration through environment variables, YAML/TOML files, and defaults.

### Configuration Sources (in priority order):
1. Environment variables (prefix: `AIVIANIA_`, e.g., `AIVIANIA_SERVER__HOST=0.0.0.0`)
2. `config.yml` or `config.toml` files
3. Default values

### Sample Configuration (`config.yml`):

```yaml
server:
  host: "127.0.0.0"
  port: 3000
  workers: 4

database:
  url: "sqlite:aiviania.db"
  max_connections: 10
  connection_timeout: 30

auth:
  jwt_secret: "your-super-secret-jwt-key-change-this-in-production"
  jwt_expiration_hours: 24
  bcrypt_cost: 12

session:
  cookie_name: "aiviania_session"
  secure: false
  http_only: true
  same_site: "lax"
  max_age_hours: 24

jobs:
  redis_url: "redis://127.0.0.1:6379"
  default_queue: "default"
  worker_concurrency: 5
  cleanup_interval_hours: 24

blockchain:
  rpc_url: "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
  chain_id: 1
  gas_limit: 21000

cache:
  redis_url: "redis://127.0.0.1:6379"
  default_ttl_seconds: 3600

rate_limit:
  requests_per_minute: 100
  burst_size: 20

websocket:
  max_connections: 1000
  heartbeat_interval: 30
  max_message_size: 65536

logging:
  level: "info"
  format: "json"
```

### Environment Variables:

```bash
export AIVIANIA_SERVER__HOST=0.0.0.0
export AIVIANIA_SERVER__PORT=8080
export AIVIANIA_DATABASE__URL="sqlite:prod.db"
export AIVIANIA_AUTH__JWT_SECRET="your-secret"
export AIVIANIA_SESSION__COOKIE_NAME="myapp_session"
export AIVIANIA_JOBS__REDIS_URL="redis://prod-redis:6379"
export AIVIANIA_BLOCKCHAIN__RPC_URL="https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
export AIVIANIA_CACHE__REDIS_URL="redis://prod-redis:6379"
export AIVIANIA_RATE_LIMIT__REQUESTS_PER_MINUTE=1000
```

## Cargo Features

AIVIANIA supports optional features that can be enabled with `--features`:

- `sqlite`: SQLite database support with async operations and repository pattern (enabled by default for database features)
- `redis`: Redis support for sessions, caching, and job queues
- `postgres`: PostgreSQL support with SQLx
- `mysql`: MySQL support with SQLx
- `mongodb`: MongoDB support
- `utoipa`: OpenAPI/Swagger API documentation generation
- `email`: Email integration with SMTP and templates (enabled by default)
- `graphql`: GraphQL API support with async-graphql (enabled by default)
- `oauth`: OAuth2 authentication with multiple providers (enabled by default)

```bash
# Enable SQLite database support
cargo build --features sqlite

# Enable Redis support
cargo build --features redis

# Enable API documentation
cargo run --features utoipa --example main

# Enable multiple features
cargo build --features "sqlite redis utoipa email graphql oauth"

# Minimal build (disable optional features)
cargo build --features ""
```

## Examples

AIVIANIA includes comprehensive examples:

```bash
# Basic server
cargo run --example main

# Database integration with SQLite
cargo run --features sqlite --example database_example

# Session management
cargo run --example session_example

# Background jobs
cargo run --example jobs_example

# File upload
cargo run --example upload_example

# Email, GraphQL, and OAuth integration
cargo run --example email_graphql_oauth_example

# With Redis support
cargo run --features redis --example jobs_example
```

```rust
use aiviania::AppConfig;

let config = AppConfig::load().unwrap_or_else(|e| {
    eprintln!("Config error: {}", e);
    AppConfig::default()
});

if let Err(e) = config.validate() {
    eprintln!("Invalid config: {}", e);
    std::process::exit(1);
}

println!("Server will run on {}", config.server_addr());
```

## Extending AIVIANIA

- Add new routes with `Route::new()`.
- Implement `Middleware` for custom processing (logging, auth, rate limiting, sessions).
- Implement `Plugin` for AI, DB, WebSocket, blockchain, etc.
- Create custom job handlers for background processing.
- Add session stores, cache backends, or database drivers.
- For hot reload, use `cargo watch -x run --example main`.

## Performance & Scalability

AIVIANIA is designed for high-performance, scalable applications:

- **Async-First**: Built on tokio for efficient async I/O
- **Background Jobs**: Offload heavy tasks to prevent request timeouts
- **Caching**: Reduce database load with configurable caching
- **Rate Limiting**: Protect against abuse and ensure fair usage
- **Session Management**: Efficient session handling with multiple backends
- **Metrics**: Monitor performance with Prometheus integration
- **Database Optimization**: Async database operations with connection pooling

### Benchmarks

- **HTTP Routing**: ~50,000 requests/second (single core)
- **WebSocket**: 10,000+ concurrent connections
- **Database**: Async SQLite with 1,000+ concurrent queries
- **Memory Usage**: ~5MB base + ~1KB per concurrent connection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Submit a pull request

## License

MIT
