//! Example demonstrating session management in AIVIANIA
//!
//! This example shows how to use the session management system
//! with different storage backends.

use aiviania::{
    request::AivianiaRequest,
    response::AivianiaResponse,
    router::{Route, Router},
    server::AivianiaServer,
    session::{SessionManager, SessionMiddleware},
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

async fn create_session_handler(_req: AivianiaRequest) -> AivianiaResponse {
    // This would typically be done in middleware or a more complex handler
    // For demonstration, we'll just return a message
    AivianiaResponse::new(StatusCode::OK).body(Body::from(
        "Session created! Check the cookies in your browser.",
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create session manager with memory store
    let session_manager = Arc::new(SessionManager::new());

    // Create router
    let mut router = Router::new();

    // Add routes (wrap existing handlers to match the Route handler signature)
    let session_manager_clone = session_manager.clone();
    router.add_route(
        Route::new("GET", "/", move |req, _plugins| {
            let _session_manager = session_manager_clone.clone();
            async move { session_example_handler(req).await }
        }),
    );

    let session_manager_clone2 = session_manager.clone();
    router.add_route(
        Route::new("GET", "/create-session", move |req, _plugins| {
            let _session_manager = session_manager_clone2.clone();
            async move { create_session_handler(req).await }
        }),
    );

    // Create server with router and attach session middleware at server level
    let server = AivianiaServer::new(router).with_middleware(Box::new(SessionMiddleware::new(
        session_manager.clone(),
    )));

    server.run("127.0.0.1:3000").await?;

    Ok(())
}
