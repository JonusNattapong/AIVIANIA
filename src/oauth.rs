use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, ClientId, ClientSecret,
    CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;
use hyper::{Body, Request, Response, StatusCode};
use std::pin::Pin;
use std::future::Future;

/// OAuth provider configuration
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProvider {
    /// Provider name (google, github, facebook, etc.)
    pub name: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Authorization URL
    pub auth_url: String,
    /// Token URL
    pub token_url: String,
    /// User info URL
    pub user_info_url: String,
    /// Scopes to request
    pub scopes: Vec<String>,
    /// Redirect URL
    pub redirect_url: String,
}

/// OAuth configuration
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    /// Enabled providers
    pub providers: HashMap<String, OAuthProvider>,
    /// Session cookie name
    pub session_cookie: String,
    /// State parameter TTL in seconds
    pub state_ttl_seconds: u64,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        let mut providers = HashMap::new();

        // Google OAuth provider
        providers.insert("google".to_string(), OAuthProvider {
            name: "google".to_string(),
            client_id: "".to_string(),
            client_secret: "".to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            redirect_url: "http://localhost:3000/auth/google/callback".to_string(),
        });

        // GitHub OAuth provider
        providers.insert("github".to_string(), OAuthProvider {
            name: "github".to_string(),
            client_id: "".to_string(),
            client_secret: "".to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string(), "read:user".to_string()],
            redirect_url: "http://localhost:3000/auth/github/callback".to_string(),
        });

        Self {
            providers,
            session_cookie: "aiviania_session".to_string(),
            state_ttl_seconds: 300, // 5 minutes
        }
    }
}

/// OAuth user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUser {
    /// Provider name
    pub provider: String,
    /// Provider user ID
    pub provider_id: String,
    /// Email address
    pub email: String,
    /// Username/display name
    pub username: Option<String>,
    /// Full name
    pub full_name: Option<String>,
    /// Avatar URL
    pub avatar_url: Option<String>,
    /// Raw user data from provider
    pub raw_data: serde_json::Value,
}

/// OAuth state data for CSRF protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// State token
    pub state: String,
    /// Provider name
    pub provider: String,
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// OAuth tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    /// Access token
    pub access_token: String,
    /// Refresh token (optional)
    pub refresh_token: Option<String>,
    /// Token type
    pub token_type: String,
    /// Expires in (seconds)
    pub expires_in: Option<u64>,
    /// Scopes
    pub scopes: Vec<String>,
}

/// OAuth service for managing multiple providers
pub struct OAuthService {
    config: OAuthConfig,
    clients: HashMap<String, BasicClient>,
    states: RwLock<HashMap<String, OAuthState>>,
}

impl OAuthService {
    /// Create a new OAuth service
    pub fn new(config: OAuthConfig) -> Result<Self, OAuthError> {
        let mut clients = HashMap::new();

        for (name, provider) in &config.providers {
            let client = BasicClient::new(
                ClientId::new(provider.client_id.clone()),
                Some(ClientSecret::new(provider.client_secret.clone())),
                AuthUrl::new(provider.auth_url.clone())?,
                Some(TokenUrl::new(provider.token_url.clone())?),
            )
            .set_redirect_uri(RedirectUrl::new(provider.redirect_url.clone())?);

            clients.insert(name.clone(), client);
        }

        Ok(Self {
            config,
            clients,
            states: RwLock::new(HashMap::new()),
        })
    }

    /// Get authorization URL for a provider
    pub async fn get_authorization_url(&self, provider: &str) -> Result<(Url, String), OAuthError> {
        let client = self.clients.get(provider)
            .ok_or_else(|| OAuthError::ProviderNotFound(provider.to_string()))?;

        let provider_config = self.config.providers.get(provider)
            .ok_or_else(|| OAuthError::ProviderNotFound(provider.to_string()))?;

        // Generate state for CSRF protection
        let state = CsrfToken::new_random();
        let state_string = state.secret().clone();

        // Store state with expiration
        let oauth_state = OAuthState {
            state: state_string.clone(),
            provider: provider.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(self.config.state_ttl_seconds as i64),
        };

        {
            let mut states = self.states.write().await;
            states.insert(state_string.clone(), oauth_state);
        }

        // Build authorization URL
        let mut auth_request = client.authorize_url(|| state);

        for scope in &provider_config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (url, _) = auth_request.url();
        Ok((url, state_string))
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(&self, provider: &str, code: &str, state: &str) -> Result<OAuthTokens, OAuthError> {
        // Verify state
        self.verify_state(state, provider).await?;

        let client = self.clients.get(provider)
            .ok_or_else(|| OAuthError::ProviderNotFound(provider.to_string()))?;

        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await?;

        let tokens = OAuthTokens {
            access_token: token_result.access_token().secret().clone(),
            refresh_token: token_result.refresh_token().map(|t| t.secret().clone()),
            token_type: token_result.token_type().as_ref().to_string(),
            expires_in: token_result.expires_in().map(|d| d.as_secs()),
            scopes: token_result.scopes()
                .map(|scopes| scopes.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
        };

        Ok(tokens)
    }

    /// Get user information from provider
    pub async fn get_user_info(&self, provider: &str, tokens: &OAuthTokens) -> Result<OAuthUser, OAuthError> {
        let provider_config = self.config.providers.get(provider)
            .ok_or_else(|| OAuthError::ProviderNotFound(provider.to_string()))?;

        let client = reqwest::Client::new();
        let response = client
            .get(&provider_config.user_info_url)
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .header("User-Agent", "AIVIANIA-OAuth/1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(OAuthError::UserInfoRequestFailed(response.status().to_string()));
        }

        let user_data: serde_json::Value = response.json().await?;

        // Parse user data based on provider
        let oauth_user = match provider {
            "google" => self.parse_google_user(user_data)?,
            "github" => self.parse_github_user(user_data).await?,
            _ => self.parse_generic_user(provider, user_data)?,
        };

        Ok(oauth_user)
    }

    /// Verify OAuth state parameter
    async fn verify_state(&self, state: &str, expected_provider: &str) -> Result<(), OAuthError> {
        let mut states = self.states.write().await;
        if let Some(stored_state) = states.remove(state) {
            if stored_state.provider != expected_provider {
                return Err(OAuthError::InvalidState("Provider mismatch".to_string()));
            }
            if chrono::Utc::now() > stored_state.expires_at {
                return Err(OAuthError::InvalidState("State expired".to_string()));
            }
            Ok(())
        } else {
            Err(OAuthError::InvalidState("State not found".to_string()))
        }
    }

    /// Parse Google user data
    fn parse_google_user(&self, data: serde_json::Value) -> Result<OAuthUser, OAuthError> {
        let user = OAuthUser {
            provider: "google".to_string(),
            provider_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().unwrap_or("").to_string(),
            username: data["name"].as_str().map(|s| s.to_string()),
            full_name: data["name"].as_str().map(|s| s.to_string()),
            avatar_url: data["picture"].as_str().map(|s| s.to_string()),
            raw_data: data,
        };
        Ok(user)
    }

    /// Parse GitHub user data
    async fn parse_github_user(&self, data: serde_json::Value) -> Result<OAuthUser, OAuthError> {
        // GitHub requires separate call for emails
        let email = if let Some(email) = data["email"].as_str() {
            email.to_string()
        } else {
            // Try to get primary email from emails endpoint
            // This would require the access token, but for simplicity we'll use the public email
            data["email"].as_str().unwrap_or("").to_string()
        };

        let user = OAuthUser {
            provider: "github".to_string(),
            provider_id: data["id"].to_string(),
            email,
            username: data["login"].as_str().map(|s| s.to_string()),
            full_name: data["name"].as_str().map(|s| s.to_string()),
            avatar_url: data["avatar_url"].as_str().map(|s| s.to_string()),
            raw_data: data,
        };
        Ok(user)
    }

    /// Parse generic OAuth user data
    fn parse_generic_user(&self, provider: &str, data: serde_json::Value) -> Result<OAuthUser, OAuthError> {
        let user = OAuthUser {
            provider: provider.to_string(),
            provider_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().unwrap_or("").to_string(),
            username: data["username"].as_str().or(data["name"].as_str()).map(|s| s.to_string()),
            full_name: data["name"].as_str().map(|s| s.to_string()),
            avatar_url: data["avatar_url"].as_str().or(data["picture"].as_str()).map(|s| s.to_string()),
            raw_data: data,
        };
        Ok(user)
    }

    /// Clean up expired states
    pub async fn cleanup_expired_states(&self) {
        let mut states = self.states.write().await;
        let now = chrono::Utc::now();
        states.retain(|_, state| state.expires_at > now);
    }

    /// Get available providers
    pub fn get_providers(&self) -> Vec<String> {
        self.config.providers.keys().cloned().collect()
    }

    /// Check if provider is configured
    pub fn is_provider_configured(&self, provider: &str) -> bool {
        self.config.providers.contains_key(provider) &&
        !self.config.providers[provider].client_id.is_empty() &&
        !self.config.providers[provider].client_secret.is_empty()
    }
}

/// OAuth errors
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("OAuth provider '{0}' not found")]
    ProviderNotFound(String),
    #[error("Invalid OAuth state: {0}")]
    InvalidState(String),
    #[error("OAuth URL construction error: {0}")]
    UrlError(#[from] oauth2::url::ParseError),
    #[error("OAuth request error: {0}")]
    RequestError(#[from] oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),
    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("User info request failed: {0}")]
    UserInfoRequestFailed(String),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// OAuth middleware for handling OAuth flows
pub struct OAuthMiddleware {
    _oauth_service: Arc<OAuthService>,
    _session_manager: Arc<crate::SessionManager>,
    _database: Arc<crate::Database>,
}

impl OAuthMiddleware {
    pub fn new(
        oauth_service: Arc<OAuthService>,
        session_manager: Arc<crate::SessionManager>,
        database: Arc<crate::Database>,
    ) -> Self {
        Self {
            _oauth_service: oauth_service,
            _session_manager: session_manager,
            _database: database,
        }
    }
}

#[async_trait::async_trait]
impl crate::Middleware for OAuthMiddleware {
    fn before(&self, req: Request<Body>) -> Pin<Box<dyn Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        // For OAuth, we don't need to modify the request before handling
        // The actual OAuth logic is handled in the route handlers
        Box::pin(async move { Ok(req) })
    }
}

impl OAuthMiddleware {
    /// Handle OAuth callback
    async fn _handle_oauth_callback(&self, req: crate::Request) -> crate::Response {
        let path_segments: Vec<&str> = req.uri().path().split('/').collect();
        if path_segments.len() < 4 {
            return crate::Response::new(StatusCode::BAD_REQUEST).body(Body::from("Invalid OAuth callback URL"));
        }

        let provider = path_segments[2]; // /auth/{provider}/callback

        // Extract query parameters
        let query = req.uri().query().unwrap_or("");
        let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        let code = match params.get("code") {
            Some(code) => code,
            None => return crate::Response::new(StatusCode::BAD_REQUEST).body(Body::from("Missing authorization code")),
        };

        let state = match params.get("state") {
            Some(state) => state,
            None => return crate::Response::new(StatusCode::BAD_REQUEST).body(Body::from("Missing state parameter")),
        };

        // Exchange code for tokens
        match self._oauth_service.exchange_code(provider, code, state).await {
            Ok(tokens) => {
                // Get user info
                match self._oauth_service.get_user_info(provider, &tokens).await {
                    Ok(user) => {
                        // In a real implementation, create or update user in database
                        // and create session
                        // For now, just return success
                        let response_data = serde_json::json!({
                            "success": true,
                            "user": user,
                            "tokens": tokens
                        });

                        crate::Response::new(StatusCode::OK)
                            .header("content-type", "application/json")
                            .json(&response_data)
                    }
                    Err(e) => {
                        crate::Response::new(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(format!("Failed to get user info: {}", e)))
                    }
                }
            }
            Err(e) => {
                crate::Response::new(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("OAuth exchange failed: {}", e)))
            }
        }
    }
}

/// OAuth handlers for HTTP routes
pub mod handlers {
    use super::*;

    /// Initiate OAuth login
    pub async fn oauth_login(
        req: crate::Request,
        oauth_service: Arc<OAuthService>,
    ) -> crate::Response {
        let path_segments: Vec<&str> = req.uri().path().split('/').collect();
        if path_segments.len() < 3 {
            return crate::Response::new(StatusCode::BAD_REQUEST).body(Body::from("Invalid OAuth login URL"));
        }

        let provider = path_segments[2]; // /auth/{provider}

        match oauth_service.get_authorization_url(provider).await {
            Ok((url, _state)) => {
                crate::Response::new(StatusCode::FOUND)
                    .header("location", &url.to_string())
            }
            Err(e) => {
                crate::Response::new(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("OAuth login failed: {}", e)))
            }
        }
    }

    /// Get OAuth providers info
    pub async fn oauth_providers(oauth_service: Arc<OAuthService>) -> crate::Response {
        let providers: Vec<serde_json::Value> = oauth_service.get_providers()
            .into_iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "configured": oauth_service.is_provider_configured(&name)
                })
            })
            .collect();

        crate::Response::new(StatusCode::OK)
            .header("content-type", "application/json")
            .json(&providers)
    }
}