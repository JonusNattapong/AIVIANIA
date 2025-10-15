//! Example demonstrating session management in AIVIANIA
//!
//! This example shows how to use the session management system
//! with different storage backends.

use aiviania::{
    request::AivianiaRequest,
    response::AivianiaResponse,
    router::{Route, Router},
    server::AivianiaServer,
    session::{MemorySessionStore, SessionManager, SessionMiddleware},
};
use hyper::{Body, StatusCode};
use std::sync::Arc;

async fn session_example_handler(req: AivianiaRequest) -> AivianiaResponse {
    // Get session from request (if exists)
    let session_data = req
        .extensions()
        .get::<aiviania::session::SessionData>()
        .cloned();

    match session_data {
        Some(session) => {
            // Get visit count from session
            let visit_count: i32 = session.get("visit_count").unwrap_or(0);

            AivianiaResponse::new(StatusCode::OK).body(Body::from(format!(
                "Welcome back! Visit count: {}",
                visit_count + 1
            )))
        }
        None => AivianiaResponse::new(StatusCode::OK)
            .body(Body::from("Welcome! This is your first visit.")),
    }
}

async fn create_session_handler(req: AivianiaRequest) -> AivianiaResponse {
    // This would typically be done in middleware or a more complex handler
    // For demonstration, we'll just return a message
    AivianiaResponse::new(StatusCode::OK).body(Body::from(
        "Session created! Check the cookies in your browser.",
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create session manager with memory store
    let session_manager = Arc::new(SessionManager::new());

    // Create session middleware
    let session_middleware = Arc::new(SessionMiddleware::new(session_manager.clone()));

    // Create router with session middleware
    let mut router = Router::new();

    // Add session middleware to the router
    router.add_middleware(session_middleware);

    // Add routes
    router.add_route(Route::get("/", session_example_handler));
    router.add_route(Route::get("/create-session", create_session_handler));

    // Create and start server
    let server = AivianiaServer::new("127.0.0.1:3000".parse()?);
    server.serve(router).await?;

    Ok(())
}
