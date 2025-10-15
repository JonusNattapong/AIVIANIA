use aiviania::security::headers::SecurityHeadersMiddleware;
use aiviania::security::cors::CorsMiddleware;
use aiviania::security::csrf::{CsrfProtection, CsrfTokenGenerator};
use aiviania::observability::middleware::MetricsMiddleware;
use aiviania::{router::Router, router::Route, server::AivianiaServer, response::Response};
use hyper::{Body, Request, StatusCode};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build router
    let mut router = Router::new();

    // Create CSRF protection and generator so we can produce tokens for the form
    let csrf = Arc::new(CsrfProtection::new(3600));
    let token_gen = CsrfTokenGenerator::new(Arc::clone(&csrf));

    // Simple form endpoint (CSRF protected)
    router.add_route(Route::new(
        "GET",
        "/form",
        move |_req: Request<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| {
            let token_gen = token_gen.clone();
            async move {
                let token = token_gen.generate_token().await;
                let cookie = token_gen.create_token_cookie(&token);
                let header = token_gen.create_token_header(&token);
                let html = format!(r#"<html><body>
                <form method='POST' action='/submit'>
                  <input type='hidden' name='csrf_token' value='{}'/>
                  <input name='message' />
                  <button type='submit'>Send</button>
                </form>
                </body></html>"#, token);

                Response::new(StatusCode::OK)
                    .header("set-cookie", cookie.as_str())
                    .header(&header.0, &header.1)
                    .body(Body::from(html))
            }
        },
    ));

    router.add_route(Route::new(
        "POST",
        "/submit",
        |req: Request<Body>, _plugins: Arc<aiviania::plugin::PluginManager>| async move {
            // In a real app you'd validate CSRF token and parse body
            Response::new(StatusCode::OK).json(&serde_json::json!({"ok": true}))
        },
    ));

    // Middleware stack
    let security_headers = SecurityHeadersMiddleware::new();
    let cors = CorsMiddleware::new(vec!["http://localhost:3000".to_string()]);
    let metrics = MetricsMiddleware::new();

    let server = AivianiaServer::new(router)
    .with_middleware(Box::new(metrics))
    .with_middleware(Box::new(security_headers))
    .with_middleware(Box::new(cors))
    .with_middleware(Box::new(csrf));

    println!("Security integration example running on 127.0.0.1:3000");
    server.run("127.0.0.1:3000").await
}
