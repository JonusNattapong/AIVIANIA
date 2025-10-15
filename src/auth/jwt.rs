//! JWT token handling and validation.
//!
//! This module provides JWT token creation, validation, and refresh
//! functionality for authentication.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// JWT token claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// Email
    pub email: String,
    /// Roles
    pub roles: Vec<String>,
    /// Permissions
    pub permissions: Vec<String>,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiration timestamp
    pub exp: u64,
    /// Token type (access or refresh)
    pub token_type: String,
}

/// JWT service configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Secret key for signing tokens
    pub secret: String,
    /// Access token expiration time
    pub access_token_expiration: Duration,
    /// Refresh token expiration time
    pub refresh_token_expiration: Duration,
    /// Issuer
    pub issuer: String,
    /// Audience
    pub audience: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key-change-in-production".to_string(),
            access_token_expiration: Duration::from_secs(15 * 60), // 15 minutes
            refresh_token_expiration: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            issuer: "aiviania".to_string(),
            audience: "aiviania-users".to_string(),
        }
    }
}

/// Errors that can occur during JWT operations
#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Token creation failed: {0}")]
    TokenCreationError(String),

    #[error("Token validation failed: {0}")]
    TokenValidationError(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,
}

/// JWT service for token management
pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    /// Create a new JWT service with configuration
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Create an access token for a user
    pub fn create_access_token(
        &self,
        user_id: &str,
        username: &str,
        email: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| JwtError::TokenCreationError(e.to_string()))?
            .as_secs();

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            roles: roles.to_vec(),
            permissions: permissions.to_vec(),
            iat: now,
            exp: now + self.config.access_token_expiration.as_secs(),
            token_type: "access".to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| JwtError::TokenCreationError(e.to_string()))
    }

    /// Create a refresh token for a user
    pub fn create_refresh_token(&self, user_id: &str) -> Result<String, JwtError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| JwtError::TokenCreationError(e.to_string()))?
            .as_secs();

        let claims = Claims {
            sub: user_id.to_string(),
            username: "".to_string(),
            email: "".to_string(),
            roles: vec![],
            permissions: vec![],
            iat: now,
            exp: now + self.config.refresh_token_expiration.as_secs(),
            token_type: "refresh".to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| JwtError::TokenCreationError(e.to_string()))
    }

    /// Validate and decode a token
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true; // Explicitly enable expiration validation

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
                _ => JwtError::TokenValidationError(e.to_string()),
            }
        })?;

        Ok(token_data.claims)
    }

    /// Extract user ID from token without full validation
    pub fn extract_user_id(&self, token: &str) -> Result<String, JwtError> {
        let claims = self.validate_token(token)?;
        Ok(claims.sub)
    }

    /// Check if token is expired
    pub fn is_token_expired(&self, token: &str) -> bool {
        match self.validate_token(token) {
            Err(JwtError::TokenExpired) => true,
            _ => false,
        }
    }

    /// Refresh an access token using a refresh token
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        user_id: &str,
        username: &str,
        email: &str,
        roles: &[String],
        permissions: &[String],
    ) -> Result<String, JwtError> {
        // Validate refresh token
        let refresh_claims = self.validate_token(refresh_token)?;

        // Check if it's a refresh token
        if refresh_claims.token_type != "refresh" {
            return Err(JwtError::InvalidToken);
        }

        // Check if user ID matches
        if refresh_claims.sub != user_id {
            return Err(JwtError::InvalidToken);
        }

        // Create new access token
        self.create_access_token(user_id, username, email, roles, permissions)
    }
}

impl Default for JwtService {
    fn default() -> Self {
        Self::new(JwtConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation_and_validation() {
        let service = JwtService::default();
        let user_id = "user123";
        let username = "testuser";
        let email = "test@example.com";
        let roles = vec!["user".to_string()];
        let permissions = vec!["read".to_string()];

        // Create access token
        let token = service
            .create_access_token(user_id, username, email, &roles, &permissions)
            .unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = service.validate_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);
        assert_eq!(claims.email, email);
        assert_eq!(claims.roles, roles);
        assert_eq!(claims.permissions, permissions);
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_refresh_token() {
        let service = JwtService::default();
        let user_id = "user123";

        // Create refresh token
        let refresh_token = service.create_refresh_token(user_id).unwrap();
        assert!(!refresh_token.is_empty());

        // Validate refresh token
        let claims = service.validate_token(&refresh_token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.token_type, "refresh");

        // Use refresh token to create new access token
        let roles = vec!["user".to_string()];
        let permissions = vec!["read".to_string()];
        let new_access_token = service
            .refresh_access_token(
                &refresh_token,
                user_id,
                "testuser",
                "test@example.com",
                &roles,
                &permissions,
            )
            .unwrap();

        // Validate new access token
        let new_claims = service.validate_token(&new_access_token).unwrap();
        assert_eq!(new_claims.sub, user_id);
        assert_eq!(new_claims.token_type, "access");
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig::default();
        let service = JwtService::new(config);

        // Create a token that should already be expired by manually setting a past expiration
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(3600); // 1 hour ago

        let claims = Claims {
            sub: "user123".to_string(),
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            roles: vec![],
            permissions: vec![],
            iat: past_time,
            exp: past_time + 1, // expired 1 hour ago
            token_type: "access".to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &service.encoding_key).unwrap();

        // Token should be expired
        assert!(service.is_token_expired(&token));
        assert!(matches!(
            service.validate_token(&token),
            Err(JwtError::TokenExpired)
        ));
    }
}
