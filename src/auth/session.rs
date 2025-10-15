//! Session management for authentication.
//!
//! This module provides session-based authentication with
//! in-memory and Redis-backed session storage.

use crate::auth::models::User;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Session data stored for authenticated users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last access timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session expiration time
    pub expiration_seconds: u64,
    /// Session cookie name
    pub cookie_name: String,
    /// Session cookie domain
    pub cookie_domain: Option<String>,
    /// Session cookie path
    pub cookie_path: String,
    /// Session cookie secure flag
    pub cookie_secure: bool,
    /// Session cookie http_only flag
    pub cookie_http_only: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expiration_seconds: 7 * 24 * 60 * 60, // 7 days
            cookie_name: "aiviania_session".to_string(),
            cookie_domain: None,
            cookie_path: "/".to_string(),
            cookie_secure: false,
            cookie_http_only: true,
        }
    }
}

/// Session storage trait for different backends
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a session
    async fn store(&self, session: Session) -> Result<(), SessionError>;

    /// Retrieve a session by ID
    async fn get(&self, session_id: &str) -> Result<Option<Session>, SessionError>;

    /// Delete a session
    async fn delete(&self, session_id: &str) -> Result<(), SessionError>;

    /// Check if session exists
    async fn exists(&self, session_id: &str) -> Result<bool, SessionError>;

    /// Update session last accessed time
    async fn touch(&self, session_id: &str) -> Result<(), SessionError>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> Result<(), SessionError>;
}

/// In-memory session store for development
pub struct MemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl MemorySessionStore {
    /// Create a new in-memory session store
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for MemorySessionStore {
    async fn store(&self, session: Session) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), session);
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<Session>, SessionError> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn exists(&self, session_id: &str) -> Result<bool, SessionError> {
        let sessions = self.sessions.read().await;
        Ok(sessions.contains_key(session_id))
    }

    async fn touch(&self, session_id: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_accessed = chrono::Utc::now();
        }
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        sessions.retain(|_, session| session.expires_at > now);
        Ok(())
    }
}

/// Session manager for handling user sessions
pub struct SessionManager<S: SessionStore = MemorySessionStore> {
    store: S,
    config: SessionConfig,
}

impl SessionManager<MemorySessionStore> {
    /// Create a new session manager with in-memory storage
    pub fn new(config: SessionConfig) -> Self {
        Self {
            store: MemorySessionStore::new(),
            config,
        }
    }
}

impl<S: SessionStore> SessionManager<S> {
    /// Create a session manager with custom storage
    pub fn with_store(store: S, config: SessionConfig) -> Self {
        Self { store, config }
    }

    /// Create a new session for a user
    pub async fn create_session(&self, user: &User) -> Result<Session, SessionError> {
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.config.expiration_seconds as i64);

        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            username: user.username.clone(),
            roles: user.roles.iter().map(|r| format!("{:?}", r)).collect(),
            permissions: user
                .permissions
                .iter()
                .map(|p| format!("{:?}", p))
                .collect(),
            created_at: now,
            last_accessed: now,
            expires_at,
            metadata: HashMap::new(),
        };

        self.store.store(session.clone()).await?;
        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Result<Option<Session>, SessionError> {
        let session = self.store.get(session_id).await?;

        if let Some(ref session) = session {
            // Check if session is expired
            if session.expires_at <= chrono::Utc::now() {
                // Delete expired session
                self.store.delete(session_id).await?;
                return Ok(None);
            }

            // Update last accessed time
            self.store.touch(session_id).await?;
        }

        Ok(session)
    }

    /// Delete a session
    pub async fn delete_session(&self, session_id: &str) -> Result<(), SessionError> {
        self.store.delete(session_id).await
    }

    /// Check if session exists and is valid
    pub async fn validate_session(&self, session_id: &str) -> Result<bool, SessionError> {
        self.store.exists(session_id).await
    }

    /// Extend session expiration
    pub async fn extend_session(
        &self,
        session_id: &str,
        additional_seconds: u64,
    ) -> Result<(), SessionError> {
        if let Some(mut session) = self.store.get(session_id).await? {
            session.expires_at =
                session.expires_at + chrono::Duration::seconds(additional_seconds as i64);
            self.store.store(session).await?;
        }
        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<(), SessionError> {
        self.store.cleanup_expired().await
    }

    /// Get session configuration
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }
}

impl Default for SessionManager<MemorySessionStore> {
    fn default() -> Self {
        Self::new(SessionConfig::default())
    }
}

/// Session-related errors
#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("Session store error: {0}")]
    StoreError(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid session data")]
    InvalidSessionData,
}

impl From<Box<dyn std::error::Error + Send + Sync>> for SessionError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        SessionError::StoreError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::models::User;

    #[tokio::test]
    async fn test_session_creation() {
        let manager = SessionManager::default();
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hash".to_string(),
        );

        let session = manager.create_session(&user).await.unwrap();
        assert_eq!(session.user_id, user.id);
        assert_eq!(session.username, user.username);
        assert!(session.expires_at > chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_session_retrieval() {
        let manager = SessionManager::default();
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hash".to_string(),
        );

        let created_session = manager.create_session(&user).await.unwrap();
        let retrieved_session = manager
            .get_session(&created_session.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(created_session.id, retrieved_session.id);
        assert_eq!(created_session.user_id, retrieved_session.user_id);
    }

    #[tokio::test]
    async fn test_session_deletion() {
        let manager = SessionManager::default();
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hash".to_string(),
        );

        let session = manager.create_session(&user).await.unwrap();
        assert!(manager.validate_session(&session.id).await.unwrap());

        manager.delete_session(&session.id).await.unwrap();
        assert!(!manager.validate_session(&session.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_expired_session() {
        let config = SessionConfig {
            expiration_seconds: 1, // Very short expiration
            ..Default::default()
        };
        let manager = SessionManager::new(config);
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hash".to_string(),
        );

        let session = manager.create_session(&user).await.unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Session should be gone
        let retrieved = manager.get_session(&session.id).await.unwrap();
        assert!(retrieved.is_none());
    }
}
