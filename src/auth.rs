//! Authentication module - JWT-based authentication middleware.
//!
//! This module provides JWT token creation, validation, and middleware for protecting routes.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use hyper::{Request, Body, StatusCode, Response};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::middleware::Middleware;
use crate::response::AivianiaResponse;
use crate::database::DatabasePlugin;
use crate::plugin::Plugin;
use std::any::Any;
// NOTE: `User` type available from crate::database when needed

/// JWT claims structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,  // Subject (user ID)
    pub exp: usize,   // Expiration time
    pub iat: usize,   // Issued at
}

/// Identity information attached to request extensions after successful auth
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub user_id: i64,
    pub username: String,
    pub roles: Vec<String>,
    pub claims: Claims,
}

/// Auth service for token management.
#[derive(Clone)]
pub struct AuthService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    /// Create a new auth service with a secret key.
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_ref()),
            decoding_key: DecodingKey::from_secret(secret.as_ref()),
        }
    }

    /// Generate a JWT token for a user.
    pub fn generate_token(&self, user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let exp = now + Duration::hours(24); // 24 hour expiration

        let claims = Claims {
            sub: user_id.to_string(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
    }

    /// Validate and decode a JWT token.
    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

impl Plugin for AuthService {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &'static str {
        "auth"
    }
}

/// Authentication middleware that checks for JWT tokens.
pub struct AuthMiddleware {
    auth_service: Arc<AuthService>,
}

impl AuthMiddleware {
    /// Create new auth middleware.
    pub fn new(auth_service: Arc<AuthService>) -> Self {
        Self { auth_service }
    }
}

impl Middleware for AuthMiddleware {
    fn before(&self, mut req: Request<Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        let auth = self.auth_service.clone();
        // attempt to clone plugin manager from request extensions for DB lookup
        Box::pin(async move {
            // Check for Authorization header
            if let Some(auth_header) = req.headers().get("authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..]; // Remove "Bearer " prefix
                        match auth.validate_token(token) {
                            Ok(claims) => {
                                // Token is valid, attempt to resolve user from DB plugin if available
                                println!("Authenticated token subject: {}", claims.sub);
                                // claims.sub represents the username in our implementation
                                if let Some(plugin_mgr_any) = req.extensions().get::<Arc<crate::plugin::PluginManager>>() {
                                    // We have a PluginManager stored in request extensions
                                    let plugin_mgr = plugin_mgr_any.clone();
                                    if let Some(db_plugin) = plugin_mgr.get("db") {
                                        if let Some(db) = db_plugin.as_any().downcast_ref::<DatabasePlugin>() {
                                            match db.db().get_user(&claims.sub).await {
                                                Ok(Some(user)) => {
                                                    // load roles
                                                    match db.db().get_user_roles(user.id).await {
                                                        Ok(roles) => {
                                                            let identity = AuthIdentity {
                                                                user_id: user.id,
                                                                username: user.username.clone(),
                                                                roles,
                                                                claims: claims.clone(),
                                                            };
                                                            req.extensions_mut().insert(identity);
                                                            return Ok(req);
                                                        }
                                                        Err(_) => {
                                                            return Err(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Failed to load roles")).unwrap());
                                                        }
                                                    }
                                                }
                                                Ok(None) => {
                                                    // Token valid but user not found
                                                    return Err(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("User not found")).unwrap());
                                                }
                                                Err(_) => {
                                                    return Err(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Database error")) .unwrap());
                                                }
                                            }
                                        }
                                    }
                                }

                                // Fallback: insert claims only when DB/plugin not available
                                req.extensions_mut().insert(claims);
                                return Ok(req);
                            }
                            Err(err) => {
                                println!("Invalid token: {}", err);
                                return Err(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("Invalid token")).unwrap());
                            }
                        }
                    }
                }
            }

            // No valid authentication provided
            Err(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("Unauthorized")).unwrap())
        })
    }
}

/// Helper function to extract user ID from request (placeholder).
pub fn get_user_id_from_request(_req: &Request<Body>) -> Option<String> {
    // Extract username/subject from claims or AuthIdentity in request extensions
    if let Some(claims) = _req.extensions().get::<Claims>() {
        return Some(claims.sub.clone());
    }

    if let Some(identity) = _req.extensions().get::<AuthIdentity>() {
        return Some(identity.username.clone());
    }

    None
}

/// Example login handler.
pub async fn login_handler(req: Request<Body>, plugins: Arc<crate::plugin::PluginManager>) -> AivianiaResponse {
    // Parse JSON body for username/password
    match hyper::body::to_bytes(req.into_body()).await {
        Ok(body) => {
            #[derive(Deserialize)]
            struct LoginRequest {
                username: String,
                password: String,
            }

            match serde_json::from_slice::<LoginRequest>(&body) {
                Ok(login_req) => {
                    // Check credentials against database
                    if let Some(db_plugin) = plugins.get("db") {
                        if let Some(db) = db_plugin.as_any().downcast_ref::<DatabasePlugin>() {
                            match db.db().verify_credentials(&login_req.username, &login_req.password).await {
                                Ok(Some(user)) => {
                                    // Generate JWT token
                                    if let Some(auth_plugin) = plugins.get("auth") {
                                        if let Some(auth_service) = auth_plugin.as_any().downcast_ref::<AuthService>() {
                                            match auth_service.generate_token(&user.username) {
                                                Ok(token) => {
                                                    #[derive(Serialize)]
                                                    struct LoginResponse {
                                                        token: String,
                                                        message: String,
                                                        user_id: i64,
                                                    }
                                                    return AivianiaResponse::new(StatusCode::OK).json(&LoginResponse {
                                                        token,
                                                        message: "Login successful".to_string(),
                                                        user_id: user.id,
                                                    });
                                                }
                                                Err(_) => {}
                                            }
                                        }
                                    }
                                    return AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Token generation failed"));
                                }
                                Ok(None) => {
                                    return AivianiaResponse::new(StatusCode::UNAUTHORIZED).body(Body::from("Invalid credentials"));
                                }
                                Err(_) => {
                                    return AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Database error"));
                                }
                            }
                        }
                    }
                    AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Database plugin not found"))
                }
                Err(_) => AivianiaResponse::new(StatusCode::BAD_REQUEST).body(Body::from("Invalid JSON")),
            }
        }
        Err(_) => AivianiaResponse::new(StatusCode::BAD_REQUEST).body(Body::from("Failed to read body")),
    }
}

/// User registration handler.
pub async fn register_handler(req: Request<Body>, plugins: Arc<crate::plugin::PluginManager>) -> AivianiaResponse {
    // Parse JSON body for username/password
    match hyper::body::to_bytes(req.into_body()).await {
        Ok(body) => {
            #[derive(Deserialize)]
            struct RegisterRequest {
                username: String,
                password: String,
            }

            match serde_json::from_slice::<RegisterRequest>(&body) {
                Ok(register_req) => {
                    // Validate input
                    if register_req.username.trim().is_empty() {
                        return AivianiaResponse::new(StatusCode::BAD_REQUEST)
                            .body(Body::from("Username cannot be empty"));
                    }

                    if register_req.username.len() < 3 {
                        return AivianiaResponse::new(StatusCode::BAD_REQUEST)
                            .body(Body::from("Username must be at least 3 characters long"));
                    }

                    if register_req.password.len() < 6 {
                        return AivianiaResponse::new(StatusCode::BAD_REQUEST)
                            .body(Body::from("Password must be at least 6 characters long"));
                    }

                    // Check if database plugin is available
                    if let Some(db_plugin) = plugins.get("db") {
                        if let Some(db) = db_plugin.as_any().downcast_ref::<DatabasePlugin>() {
                            // Check if user already exists
                            match db.db().get_user(&register_req.username).await {
                                Ok(Some(_)) => {
                                    return AivianiaResponse::new(StatusCode::CONFLICT)
                                        .body(Body::from("Username already exists"));
                                }
                                Ok(None) => {
                                    // User doesn't exist, proceed with registration
                                }
                                Err(_) => {
                                    return AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("Database error"));
                                }
                            }

                            // Hash the password
                            match crate::database::Database::hash_password(&register_req.password) {
                                Ok(password_hash) => {
                                    // Create the user
                                    match db.db().create_user(&register_req.username, &password_hash).await {
                                        Ok(user_id) => {
                                            // Assign default "user" role
                                            if let Err(_) = db.db().assign_role_to_user(user_id, "user").await {
                                                return AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                                    .body(Body::from("Failed to assign user role"));
                                            }

                                            #[derive(Serialize)]
                                            struct RegisterResponse {
                                                message: String,
                                                user_id: i64,
                                                username: String,
                                                role: String,
                                            }
                                            AivianiaResponse::new(StatusCode::CREATED).json(&RegisterResponse {
                                                message: "User registered successfully".to_string(),
                                                user_id,
                                                username: register_req.username,
                                                role: "user".to_string(),
                                            })
                                        }
                                        Err(_) => {
                                            AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Body::from("Failed to create user"))
                                        }
                                    }
                                }
                                Err(_) => {
                                    AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("Password hashing failed"))
                                }
                            }
                        } else {
                            AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Database plugin type mismatch"))
                        }
                    } else {
                        AivianiaResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from("Database plugin not found"))
                    }
                }
                Err(_) => AivianiaResponse::new(StatusCode::BAD_REQUEST).body(Body::from("Invalid JSON")),
            }
        }
        Err(_) => AivianiaResponse::new(StatusCode::BAD_REQUEST).body(Body::from("Failed to read body")),
    }
}