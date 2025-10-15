use aiviania::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal example: initialize email service if available and run a tiny server
    let config = AppConfig::from_env();

    // If EmailService is available, create a simple instance; otherwise skip
    #[allow(unused_variables)]
    let _email = if cfg!(feature = "email") {
        let ec = EmailConfig {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "user".to_string(),
            smtp_password: "pass".to_string(),
            use_tls: false,
            from_email: "noreply@example.com".to_string(),
            from_name: "Example".to_string(),
            templates_dir: "./templates".to_string(),
        };
        Some(Arc::new(EmailService::new(ec)?))
    } else {
        None
    };

    println!("Minimal email example - nothing to run interactively.");
    Ok(())
}
use aiviania::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Example demonstrating Email, GraphQL, and OAuth integration
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the server
    let mut server = AivianiaServer::new();

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

    // Configure GraphQL service
    let graphql_config = GraphQLConfig {
        enable_playground: true,
        path: "/graphql".to_string(),
        enable_introspection: true,
        max_complexity: Some(1000),
        max_depth: Some(10),
    };

    let graphql_service = Arc::new(GraphQLService::new(graphql_config));

    // Configure OAuth service
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

    // Initialize services
    let database = Arc::new(Database::new().await?);
    let session_manager = Arc::new(SessionManager::new());
    let auth_service = Arc::new(AuthService::new(database.clone()));

    // Initialize email verification and password reset services
    let email_verification = Arc::new(EmailVerificationService::new(email_service.clone()));
    let password_reset = Arc::new(PasswordResetService::new(email_service.clone()));

    // Add middleware
    server.add_middleware(SessionMiddleware::new(session_manager.clone()));
    server.add_middleware(AuthMiddleware::new(auth_service.clone()));
    server.add_middleware(GraphQLMiddleware::new(
        session_manager.clone(),
        database.clone(),
    ));
    server.add_middleware(OAuthMiddleware::new(
        oauth_service.clone(),
        session_manager.clone(),
        database.clone(),
    ));

    // Email routes
    server.add_route(Route::post(
        "/api/auth/register",
        register_with_email_handler,
    ));
    server.add_route(Route::post("/api/auth/verify-email", verify_email_handler));
    server.add_route(Route::post(
        "/api/auth/forgot-password",
        forgot_password_handler,
    ));
    server.add_route(Route::post(
        "/api/auth/reset-password",
        reset_password_handler,
    ));

    // GraphQL routes
    server.add_route(Route::get("/graphql", graphql_playground_handler));
    server.add_route(Route::post("/graphql", graphql_endpoint_handler));

    // OAuth routes
    server.add_route(Route::get("/auth/google", oauth_login_handler));
    server.add_route(Route::get("/auth/github", oauth_login_handler));
    server.add_route(Route::get("/auth/google/callback", oauth_callback_handler));
    server.add_route(Route::get("/auth/github/callback", oauth_callback_handler));
    server.add_route(Route::get("/api/auth/providers", oauth_providers_handler));

    // Store services in server state for handlers
    server.state.insert("email_service", email_service);
    server
        .state
        .insert("email_verification", email_verification);
    server.state.insert("password_reset", password_reset);
    server.state.insert("graphql_service", graphql_service);
    server.state.insert("oauth_service", oauth_service);
    server.state.insert("database", database);
    server.state.insert("auth_service", auth_service);

    println!("🚀 AIVIANIA Server with Email, GraphQL, and OAuth integration");
    println!("📧 Email service configured with SMTP");
    println!("🔗 GraphQL playground available at http://localhost:3000/graphql");
    println!("🔐 OAuth providers: Google, GitHub");
    println!("📡 Server starting on http://localhost:3000");

    server.run("127.0.0.1:3000").await?;

    Ok(())
}

// Email handlers
async fn register_with_email_handler(req: Request) -> Response {
    let email_service = req.state::<Arc<EmailService>>("email_service").unwrap();
    let email_verification = req
        .state::<Arc<EmailVerificationService>>("email_verification")
        .unwrap();

    #[derive(serde::Deserialize)]
    struct RegisterRequest {
        email: String,
        password: String,
        username: String,
    }

    match serde_json::from_slice::<RegisterRequest>(req.body()) {
        Ok(register_req) => {
            // In a real app, you'd create the user in the database first
            let user_id = uuid::Uuid::new_v4().to_string();

            // Send verification email
            match email_verification
                .send_verification(&register_req.email, &user_id)
                .await
            {
                Ok(token) => {
                    let response = serde_json::json!({
                        "success": true,
                        "message": "Registration successful. Please check your email for verification.",
                        "user_id": user_id,
                        "verification_token": token
                    });

                    Response::new(201)
                        .with_header("content-type", "application/json")
                        .with_body(response.to_string())
                }
                Err(e) => Response::new(500)
                    .with_body(format!("Failed to send verification email: {}", e)),
            }
        }
        Err(_) => Response::new(400).with_body("Invalid request body"),
    }
}

async fn verify_email_handler(req: Request) -> Response {
    let email_verification = req
        .state::<Arc<EmailVerificationService>>("email_verification")
        .unwrap();

    #[derive(serde::Deserialize)]
    struct VerifyRequest {
        token: String,
    }

    match serde_json::from_slice::<VerifyRequest>(req.body()) {
        Ok(verify_req) => {
            match email_verification.verify_token(&verify_req.token).await {
                Ok(verification_data) => {
                    // In a real app, you'd update the user's verification status in the database
                    let response = serde_json::json!({
                        "success": true,
                        "message": "Email verified successfully",
                        "user_id": verification_data.user_id,
                        "email": verification_data.email
                    });

                    Response::new(200)
                        .with_header("content-type", "application/json")
                        .with_body(response.to_string())
                }
                Err(e) => Response::new(400).with_body(format!("Verification failed: {}", e)),
            }
        }
        Err(_) => Response::new(400).with_body("Invalid request body"),
    }
}

async fn forgot_password_handler(req: Request) -> Response {
    let password_reset = req
        .state::<Arc<PasswordResetService>>("password_reset")
        .unwrap();

    #[derive(serde::Deserialize)]
    struct ForgotRequest {
        email: String,
    }

    match serde_json::from_slice::<ForgotRequest>(req.body()) {
        Ok(forgot_req) => {
            // In a real app, you'd look up the user by email first
            let user_id = "user_id_from_database";

            match password_reset
                .send_reset_email(&forgot_req.email, user_id)
                .await
            {
                Ok(token) => {
                    let response = serde_json::json!({
                        "success": true,
                        "message": "Password reset email sent. Please check your email.",
                        "reset_token": token
                    });

                    Response::new(200)
                        .with_header("content-type", "application/json")
                        .with_body(response.to_string())
                }
                Err(e) => {
                    Response::new(500).with_body(format!("Failed to send reset email: {}", e))
                }
            }
        }
        Err(_) => Response::new(400).with_body("Invalid request body"),
    }
}

async fn reset_password_handler(req: Request) -> Response {
    let password_reset = req
        .state::<Arc<PasswordResetService>>("password_reset")
        .unwrap();

    #[derive(serde::Deserialize)]
    struct ResetRequest {
        token: String,
        new_password: String,
    }

    match serde_json::from_slice::<ResetRequest>(req.body()) {
        Ok(reset_req) => {
            match password_reset.verify_reset_token(&reset_req.token).await {
                Ok(reset_data) => {
                    // In a real app, you'd update the user's password in the database
                    let response = serde_json::json!({
                        "success": true,
                        "message": "Password reset successfully",
                        "user_id": reset_data.user_id,
                        "email": reset_data.email
                    });

                    Response::new(200)
                        .with_header("content-type", "application/json")
                        .with_body(response.to_string())
                }
                Err(e) => Response::new(400).with_body(format!("Password reset failed: {}", e)),
            }
        }
        Err(_) => Response::new(400).with_body("Invalid request body"),
    }
}

// GraphQL handlers
async fn graphql_playground_handler(_req: Request) -> Response {
    let html = async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql")
            .title("AIVIANIA GraphQL Playground"),
    );
    Response::new(200)
        .with_header("content-type", "text/html")
        .with_body(html)
}

async fn graphql_endpoint_handler(req: Request) -> Response {
    let graphql_service = req.state::<Arc<GraphQLService>>("graphql_service").unwrap();
    let session_manager = req.state::<Arc<SessionManager>>("session_manager").unwrap();
    let database = req.state::<Arc<Database>>("database").unwrap();

    // Extract user ID from session (simplified)
    let current_user_id = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| {
            if auth.starts_with("Bearer ") {
                Some(auth.trim_start_matches("Bearer ").to_string())
            } else {
                None
            }
        });

    let context = GraphQLContext::new(current_user_id, database.clone(), session_manager.clone());

    match async_graphql_axum::GraphQLRequest::from(req).await {
        Ok(graphql_req) => {
            let response = graphql_service.execute(graphql_req, context).await;
            response.into_response()
        }
        Err(err) => Response::new(400)
            .with_header("content-type", "application/json")
            .with_body(format!("{{\"error\": \"{}\"}}", err)),
    }
}

// OAuth handlers
async fn oauth_login_handler(req: Request) -> Response {
    let oauth_service = req.state::<Arc<OAuthService>>("oauth_service").unwrap();

    let path_segments: Vec<&str> = req.uri().path().split('/').collect();
    if path_segments.len() < 3 {
        return Response::new(400).with_body("Invalid OAuth login URL");
    }

    let provider = path_segments[2]; // /auth/{provider}

    match oauth_service.get_authorization_url(provider).await {
        Ok((url, _state)) => Response::new(302).with_header("location", url.to_string()),
        Err(e) => Response::new(400).with_body(format!("OAuth login failed: {}", e)),
    }
}

async fn oauth_callback_handler(req: Request) -> Response {
    let oauth_service = req.state::<Arc<OAuthService>>("oauth_service").unwrap();

    let path_segments: Vec<&str> = req.uri().path().split('/').collect();
    if path_segments.len() < 4 {
        return Response::new(400).with_body("Invalid OAuth callback URL");
    }

    let provider = path_segments[2]; // /auth/{provider}/callback

    // Extract query parameters
    let query = req.uri().query().unwrap_or("");
    let params: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

    let code = match params.get("code") {
        Some(code) => code,
        None => return Response::new(400).with_body("Missing authorization code"),
    };

    let state = match params.get("state") {
        Some(state) => state,
        None => return Response::new(400).with_body("Missing state parameter"),
    };

    // Exchange code for tokens
    match oauth_service.exchange_code(provider, code, state).await {
        Ok(tokens) => {
            // Get user info
            match oauth_service.get_user_info(provider, &tokens).await {
                Ok(user) => {
                    // In a real implementation, create or update user in database
                    // and create session
                    let response_data = serde_json::json!({
                        "success": true,
                        "message": "OAuth authentication successful",
                        "user": user,
                        "provider": provider
                    });

                    Response::new(200)
                        .with_header("content-type", "application/json")
                        .with_body(response_data.to_string())
                }
                Err(e) => Response::new(500).with_body(format!("Failed to get user info: {}", e)),
            }
        }
        Err(e) => Response::new(400).with_body(format!("OAuth exchange failed: {}", e)),
    }
}

async fn oauth_providers_handler(req: Request) -> Response {
    let oauth_service = req.state::<Arc<OAuthService>>("oauth_service").unwrap();

    let providers: Vec<serde_json::Value> = oauth_service
        .get_providers()
        .into_iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "configured": oauth_service.is_provider_configured(&name)
            })
        })
        .collect();

    Response::new(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&providers).unwrap())
}
