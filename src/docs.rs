//! API Documentation module using OpenAPI/Swagger
//!
//! Provides automatic OpenAPI specification generation and Swagger UI.

#[cfg(feature = "utoipa")]
use axum::Router;
#[cfg(feature = "utoipa")]
use utoipa::OpenApi;
#[cfg(feature = "utoipa")]
use utoipa_swagger_ui::SwaggerUi;

/// OpenAPI specification for the AIVIANIA API
#[cfg(feature = "utoipa")]
#[derive(OpenApi)]
#[openapi(
    info(
        title = "AIVIANIA API",
        version = "0.1.3",
        description = "Minimal async-first Rust Web Framework API",
        contact(
            name = "AIVIANIA Team",
            url = "https://github.com/JonusNattapong/AIVIANIA"
        )
    ),
    paths(
        // Add API paths here as they are implemented
    ),
    components(
        schemas(
            crate::auth::LoginRequest,
            crate::auth::RegisterRequest,
            crate::database::User
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "users", description = "User management endpoints"),
        (name = "blockchain", description = "Blockchain integration endpoints")
    )
)]
pub struct ApiDoc;

/// Create a router with Swagger UI
#[cfg(feature = "utoipa")]
pub fn swagger_ui() -> Router {
    Router::new().merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
}

/// Get the OpenAPI JSON specification
#[cfg(feature = "utoipa")]
pub fn openapi_spec() -> String {
    serde_json::to_string_pretty(&ApiDoc::openapi()).unwrap_or_default()
}