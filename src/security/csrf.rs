//! CSRF (Cross-Site Request Forgery) Protection

use super::{SecurityError, SecurityEvent, SecurityMiddleware, SecurityResult};
use async_trait::async_trait;
use hyper::{Body, Request};
use rand::Rng;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// CSRF protection middleware
pub struct CsrfProtection {
    token_store: Arc<RwLock<HashSet<String>>>,
    _token_lifetime_secs: u64,
    cookie_name: String,
    header_name: String,
    exempt_methods: HashSet<String>,
}

impl CsrfProtection {
    /// Create a new CSRF protection middleware
    pub fn new(token_lifetime_secs: u64) -> Self {
        Self {
            token_store: Arc::new(RwLock::new(HashSet::new())),
            _token_lifetime_secs: token_lifetime_secs,
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            exempt_methods: HashSet::from([
                "GET".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
            ]),
        }
    }

    /// Generate a new CSRF token
    pub fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let token: String = (0..32).map(|_| format!("{:x}", rng.gen::<u8>())).collect();
        token
    }

    /// Validate CSRF token
    pub async fn validate_token(&self, token: &str) -> bool {
        let tokens = self.token_store.read().await;
        tokens.contains(token)
    }

    /// Store a CSRF token
    pub async fn store_token(&self, token: String) {
        let mut tokens = self.token_store.write().await;
        tokens.insert(token);
    }

    /// Remove a CSRF token
    pub async fn remove_token(&self, token: &str) {
        let mut tokens = self.token_store.write().await;
        tokens.remove(token);
    }

    /// Extract token from request
    fn extract_token_from_request(&self, request: &Request<Body>) -> Option<String> {
        // Try header first
        if let Some(token) = request.headers().get(&self.header_name) {
            if let Ok(token_str) = token.to_str() {
                return Some(token_str.to_string());
            }
        }

        // Try query parameters (avoid consuming the body in middleware)
        if let Some(q) = request.uri().query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                if k == "csrf_token" {
                    return Some(v.into_owned());
                }
            }
        }

        // Try cookie
        if let Some(cookie_header) = request.headers().get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if cookie.starts_with(&format!("{}=", self.cookie_name)) {
                        return Some(cookie[self.cookie_name.len() + 1..].to_string());
                    }
                }
            }
        }

        None
    }

    /// Check if request method is exempt from CSRF protection
    fn is_method_exempt(&self, method: &hyper::Method) -> bool {
        self.exempt_methods.contains(&method.as_str().to_string())
    }

    /// Clean up expired tokens (should be called periodically)
    pub async fn cleanup_expired_tokens(&self) {
        // In a real implementation, you'd track token creation times
        // and remove expired ones. For simplicity, we'll skip this.
    }
}

#[async_trait]
impl SecurityMiddleware for CsrfProtection {
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Skip CSRF check for exempt methods
        if self.is_method_exempt(request.method()) {
            return Ok(request);
        }

        // Extract token from request
        let token = match self.extract_token_from_request(&request) {
            Some(token) => token,
            None => {
                // Log CSRF attempt
                let event = SecurityEvent::CsrfAttackAttempt {
                    ip: "unknown".to_string(), // Would extract from request in real impl
                    user_agent: request
                        .headers()
                        .get("user-agent")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string()),
                    url: request.uri().to_string(),
                    timestamp: chrono::Utc::now(),
                };
                event_logger.log_event(event).await;

                return Err(SecurityError::CsrfValidation(
                    "CSRF token missing".to_string(),
                ));
            }
        };

        // Validate token
        if !self.validate_token(&token).await {
            // Log CSRF attempt
            let event = SecurityEvent::CsrfAttackAttempt {
                ip: "unknown".to_string(),
                user_agent: request
                    .headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string()),
                url: request.uri().to_string(),
                timestamp: chrono::Utc::now(),
            };
            event_logger.log_event(event).await;

            return Err(SecurityError::CsrfValidation(
                "Invalid CSRF token".to_string(),
            ));
        }

        // Remove used token (one-time use)
        self.remove_token(&token).await;

        Ok(request)
    }
}

/// CSRF token generator for responses
pub struct CsrfTokenGenerator {
    protection: Arc<CsrfProtection>,
}

impl CsrfTokenGenerator {
    /// Create a new token generator
    pub fn new(protection: Arc<CsrfProtection>) -> Self {
        Self { protection }
    }

    /// Generate and store a new token
    pub async fn generate_token(&self) -> String {
        let token = CsrfProtection::generate_token();
        self.protection.store_token(token.clone()).await;
        token
    }

    /// Create CSRF token cookie
    pub fn create_token_cookie(&self, token: &str) -> String {
        format!(
            "{}={}; HttpOnly; Secure; SameSite=Strict; Path=/",
            self.protection.cookie_name, token
        )
    }

    /// Create CSRF token response header
    pub fn create_token_header(&self, token: &str) -> (String, String) {
        (self.protection.header_name.clone(), token.to_string())
    }
}

/// Double submit cookie pattern implementation
pub struct DoubleSubmitCookieProtection {
    cookie_name: String,
    header_name: String,
    exempt_methods: HashSet<String>,
}

impl DoubleSubmitCookieProtection {
    /// Create a new double submit cookie protection
    pub fn new() -> Self {
        Self {
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            exempt_methods: HashSet::from([
                "GET".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
            ]),
        }
    }

    /// Extract token from cookie
    fn extract_cookie_token(&self, request: &Request<Body>) -> Option<String> {
        if let Some(cookie_header) = request.headers().get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if cookie.starts_with(&format!("{}=", self.cookie_name)) {
                        return Some(cookie[self.cookie_name.len() + 1..].to_string());
                    }
                }
            }
        }
        None
    }

    /// Extract token from header
    fn extract_header_token(&self, request: &Request<Body>) -> Option<String> {
        request
            .headers()
            .get(&self.header_name)
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
    }
}

#[async_trait]
impl SecurityMiddleware for DoubleSubmitCookieProtection {
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Skip CSRF check for exempt methods
        if self
            .exempt_methods
            .contains(&request.method().as_str().to_string())
        {
            return Ok(request);
        }

        let cookie_token = self.extract_cookie_token(&request);
        let header_token = self.extract_header_token(&request);

        match (cookie_token, header_token) {
            (Some(cookie), Some(header)) => {
                if cookie != header {
                    // Log CSRF attempt
                    let event = SecurityEvent::CsrfAttackAttempt {
                        ip: "unknown".to_string(),
                        user_agent: request
                            .headers()
                            .get("user-agent")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string()),
                        url: request.uri().to_string(),
                        timestamp: chrono::Utc::now(),
                    };
                    event_logger.log_event(event).await;

                    return Err(SecurityError::CsrfValidation(
                        "CSRF token mismatch".to_string(),
                    ));
                }
            }
            _ => {
                // Log CSRF attempt
                let event = SecurityEvent::CsrfAttackAttempt {
                    ip: "unknown".to_string(),
                    user_agent: request
                        .headers()
                        .get("user-agent")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string()),
                    url: request.uri().to_string(),
                    timestamp: chrono::Utc::now(),
                };
                event_logger.log_event(event).await;

                return Err(SecurityError::CsrfValidation(
                    "CSRF tokens missing".to_string(),
                ));
            }
        }

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    #[test]
    fn test_generate_and_store_token() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let protection = Arc::new(CsrfProtection::new(3600));
            let token = CsrfProtection::generate_token();
            protection.store_token(token.clone()).await;
            assert!(protection.validate_token(&token).await);
            protection.remove_token(&token).await;
            assert!(!protection.validate_token(&token).await);
        });
    }
}
