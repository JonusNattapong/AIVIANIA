use aiviania::auth::AuthService;
use aiviania::database::Database;
use aiviania::database::DatabasePlugin;
use aiviania::middleware::RoleMiddleware;
use aiviania::plugin::PluginManager;
use aiviania::AuthMiddleware;
use aiviania::*;
use hyper::{Body, Request, StatusCode};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use tokio::task;

#[tokio::test]
async fn integration_register_login_rbac() {
    // Build router with auth and db routes
    let mut router = Router::new();

    router.add_route(Route::new("POST", "/register", auth::register_handler));
    router.add_route(Route::new("POST", "/login", auth::login_handler));

    // Initialize database and auth
    let db = Arc::new(Database::new().await.expect("db create"));
    db.create_default_roles().await.expect("create roles");

    let auth_service = Arc::new(AuthService::new("integration-secret-key-which-is-long"));

    // Protected routes
    router.add_route(
        Route::new(
            "GET",
            "/user/profile",
            |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
                Response::new(StatusCode::OK).json(&json!({"ok": true, "role": "user"}))
            },
        )
        .with_middleware(Box::new(AuthMiddleware::new(auth_service.clone())))
        .with_middleware(Box::new(RoleMiddleware::new("user", db.clone()))),
    );

    router.add_route(
        Route::new(
            "GET",
            "/admin/dashboard",
            |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
                Response::new(StatusCode::OK).json(&json!({"ok": true, "role": "admin"}))
            },
        )
        .with_middleware(Box::new(AuthMiddleware::new(auth_service.clone())))
        .with_middleware(Box::new(RoleMiddleware::new("admin", db.clone()))),
    );

    // Create server and plugins
    let plugins = PluginManager::new();
    // Add DB and Auth as plugins so handlers can find them
    let mut plugin_mgr = plugins;
    plugin_mgr.add(Box::new(DatabasePlugin::new(db.clone())));
    plugin_mgr.add(Box::new(AuthService::new(
        "integration-secret-key-which-is-long",
    )));
    let plugins = Arc::new(plugin_mgr);

    let server = AivianiaServer::new(router)
        .with_plugin(Box::new(DatabasePlugin::new(db.clone())))
        .with_plugin(Box::new(AuthService::new(
            "integration-secret-key-which-is-long",
        )));

    // Run server in background
    let addr = "127.0.0.1:4002";
    let server_task = task::spawn(async move {
        server.run(addr).await.unwrap();
    });

    // Wait for server
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let client = Client::new();

    // Register a user
    let register_resp = client
        .post(&format!("http://{}/register", addr))
        .json(&json!({"username": "itest", "password": "password123"}))
        .send()
        .await
        .expect("register request");

    assert_eq!(register_resp.status(), StatusCode::CREATED);
    let register_json: serde_json::Value = register_resp.json().await.expect("parse register json");
    assert_eq!(register_json["username"], "itest");

    // Login
    let login_resp = client
        .post(&format!("http://{}/login", addr))
        .json(&json!({"username": "itest", "password": "password123"}))
        .send()
        .await
        .expect("login request");
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_json: serde_json::Value = login_resp.json().await.expect("parse login json");
    let token = login_json["token"].as_str().expect("token");

    // Access user profile
    let profile_resp = client
        .get(&format!("http://{}/user/profile", addr))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("profile request");
    assert_eq!(profile_resp.status(), StatusCode::OK);

    // Admin access should be forbidden
    let admin_resp = client
        .get(&format!("http://{}/admin/dashboard", addr))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("admin request");
    assert_eq!(admin_resp.status(), StatusCode::FORBIDDEN);

    // Create admin user directly in DB
    let pw = Database::hash_password("adminpass").expect("hash");
    let admin_id = db
        .create_user("admin_integration", &pw)
        .await
        .expect("create admin");
    db.assign_role_to_user(admin_id, "admin")
        .await
        .expect("assign role");

    // Login as admin
    let login_admin_resp = client
        .post(&format!("http://{}/login", addr))
        .json(&json!({"username": "admin_integration", "password": "adminpass"}))
        .send()
        .await
        .expect("login admin");
    assert_eq!(login_admin_resp.status(), StatusCode::OK);
    let login_admin_json: serde_json::Value =
        login_admin_resp.json().await.expect("parse admin login");
    let admin_token = login_admin_json["token"].as_str().expect("admin token");

    // Access admin dashboard
    let admin_ok = client
        .get(&format!("http://{}/admin/dashboard", addr))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await
        .expect("admin ok");
    assert_eq!(admin_ok.status(), StatusCode::OK);

    // Shutdown server
    server_task.abort();
}
