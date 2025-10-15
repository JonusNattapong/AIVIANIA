//! Password hashing and verification utilities.
//!
//! This module provides secure password hashing using Argon2
//! and utilities for password validation.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;

/// Errors that can occur during password operations
#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("Password hashing failed: {0}")]
    HashingError(String),

    #[error("Password verification failed: {0}")]
    VerificationError(String),

    #[error("Invalid password hash format")]
    InvalidHashFormat,
}

/// Service for password hashing and verification
pub struct PasswordService {
    argon2: Argon2<'static>,
}

impl PasswordService {
    /// Create a new password service with default configuration
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(&self, password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| PasswordError::HashingError(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash = PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHashFormat)?;

        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(PasswordError::VerificationError(e.to_string())),
        }
    }

    /// Validate password strength
    pub fn validate_password_strength(&self, password: &str) -> Result<(), PasswordError> {
        if password.len() < 8 {
            return Err(PasswordError::VerificationError(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        if !password.chars().any(|c| c.is_uppercase()) {
            return Err(PasswordError::VerificationError(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        if !password.chars().any(|c| c.is_lowercase()) {
            return Err(PasswordError::VerificationError(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        if !password.chars().any(|c| c.is_numeric()) {
            return Err(PasswordError::VerificationError(
                "Password must contain at least one number".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for PasswordService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let service = PasswordService::new();
        let password = "test_password_123";

        let hash = service.hash_password(password).unwrap();
        assert!(!hash.is_empty());

        let is_valid = service.verify_password(password, &hash).unwrap();
        assert!(is_valid);

        let is_invalid = service.verify_password("wrong_password", &hash).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_password_validation() {
        let service = PasswordService::new();

        // Valid password
        assert!(service.validate_password_strength("ValidPass123").is_ok());

        // Too short
        assert!(service.validate_password_strength("Short1").is_err());

        // No uppercase
        assert!(service.validate_password_strength("lowercase123").is_err());

        // No lowercase
        assert!(service.validate_password_strength("UPPERCASE123").is_err());

        // No numbers
        assert!(service.validate_password_strength("NoNumbers").is_err());
    }
}
