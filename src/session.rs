//! Session management module.
//!
//! Provides session handling with configurable storage backends and secure cookie management.

use crate::middleware::Middleware;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use cookie::{Cookie, SameSite};
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Session data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub id: String,
    pub data: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SessionData {
    /// Create a new session with default expiration (24 hours)
    pub fn new() -> Self {
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::hours(24);

        Self {
            id,
            data: HashMap::new(),
            created_at,
            expires_at,
        }
    }

    /// Create a new session with custom expiration
    pub fn with_expiry(duration: Duration) -> Self {
        let mut session = Self::new();
        session.expires_at = session.created_at + duration;
        session
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Set a value in the session
    pub fn set<T: Serialize>(&mut self, key: &str, value: T) {
        self.data
            .insert(key.to_string(), serde_json::to_value(value).unwrap());
    }

    /// Get a value from the session
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.data
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Remove a value from the session
    pub fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    /// Clear all session data
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// Session store trait for different storage backends
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a session
    async fn store(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Load a session by ID
    async fn load(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn std::error::Error + Send + Sync>>;

    /// Delete a session
    async fn delete(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory session store for development/testing
pub struct MemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn store(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn load(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn std::error::Error + Send + Sync>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    async fn delete(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sessions = self.sessions.write().await;
        let _now = Utc::now();
        sessions.retain(|_, session| !session.is_expired());
        Ok(())
    }
}

/// Redis session store for production use
#[cfg(feature = "redis")]
pub struct RedisSessionStore {
    client: redis::Client,
}

#[cfg(feature = "redis")]
impl RedisSessionStore {
    pub fn new(redis_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn store(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let key = format!("session:{}", session.id);
        let data = serde_json::to_string(session)?;
        let ttl = (session.expires_at - Utc::now()).num_seconds().max(0) as usize;

        redis::pipe()
            .set(&key, &data)
            .expire(&key, ttl)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    async fn load(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let key = format!("session:{}", session_id);

        let data: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;

        match data {
            Some(json) => {
                let session: SessionData = serde_json::from_str(&json)?;
                if session.is_expired() {
                    self.delete(session_id).await?;
                    Ok(None)
                } else {
                    Ok(Some(session))
                }
            }
            None => Ok(None),
        }
    }

    async fn delete(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let key = format!("session:{}", session_id);
        redis::cmd("DEL").arg(&key).query_async(&mut conn).await?;
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Redis handles expiration automatically with TTL
        Ok(())
    }
}

/// Database session store using the framework's database abstraction
pub struct DatabaseSessionStore {
    _database: Arc<dyn crate::database::DatabaseConnection>,
}

impl DatabaseSessionStore {
    pub fn new(database: Arc<dyn crate::database::DatabaseConnection>) -> Self {
        Self {
            _database: database,
        }
    }
}

#[async_trait]
impl SessionStore for DatabaseSessionStore {
    async fn store(
        &self,
        _session: &SessionData,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // This would require extending the database trait to support sessions
        // For now, we'll implement a basic version that could be extended
        // In a real implementation, you'd add session table operations to DatabaseConnection
        Err("Database session store not fully implemented - requires schema changes".into())
    }

    async fn load(
        &self,
        _session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn std::error::Error + Send + Sync>> {
        Err("Database session store not fully implemented - requires schema changes".into())
    }

    async fn delete(
        &self,
        _session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Database session store not fully implemented - requires schema changes".into())
    }

    async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Database session store not fully implemented - requires schema changes".into())
    }
}

/// Session manager for handling session lifecycle
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    cookie_name: String,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
}

impl SessionManager {
    /// Create a new session manager with memory store
    pub fn new() -> Self {
        Self {
            store: Arc::new(MemorySessionStore::new()),
            cookie_name: "aiviania_session".to_string(),
            secure: false,
            http_only: true,
            same_site: SameSite::Lax,
        }
    }

    /// Create session manager with custom store
    pub fn with_store(store: Arc<dyn SessionStore>) -> Self {
        Self {
            store,
            cookie_name: "aiviania_session".to_string(),
            secure: false,
            http_only: true,
            same_site: SameSite::Lax,
        }
    }

    /// Configure cookie settings
    pub fn with_cookie_config(
        mut self,
        name: &str,
        secure: bool,
        http_only: bool,
        same_site: SameSite,
    ) -> Self {
        self.cookie_name = name.to_string();
        self.secure = secure;
        self.http_only = http_only;
        self.same_site = same_site;
        self
    }

    /// Create a new session
    pub async fn create_session(
        &self,
    ) -> Result<SessionData, Box<dyn std::error::Error + Send + Sync>> {
        let session = SessionData::new();
        self.store.store(&session).await?;
        Ok(session)
    }

    /// Get session from request cookies
    pub async fn get_session(
        &self,
        req: &Request<Body>,
    ) -> Result<Option<SessionData>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(cookie_header) = req.headers().get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in Cookie::split_parse(cookie_str) {
                    if let Ok(cookie) = cookie {
                        if cookie.name() == self.cookie_name {
                            return self.store.load(cookie.value()).await;
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Save session and return response with session cookie
    pub async fn save_session(
        &self,
        mut response: Response<Body>,
        session: &SessionData,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        self.store.store(session).await?;

        let mut cookie = Cookie::new(self.cookie_name.clone(), session.id.clone());
        cookie.set_http_only(self.http_only);
        cookie.set_secure(self.secure);
        cookie.set_same_site(self.same_site);
        cookie.set_path("/");

        // Set max-age based on session expiration
        let max_age = (session.expires_at - Utc::now()).num_seconds().max(0);
        cookie.set_max_age(cookie::time::Duration::seconds(max_age));

        response
            .headers_mut()
            .insert("set-cookie", cookie.to_string().parse().unwrap());

        Ok(response)
    }

    /// Delete session and return response with expired cookie
    pub async fn destroy_session(
        &self,
        mut response: Response<Body>,
        session_id: &str,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        self.store.delete(session_id).await?;

        let mut cookie = Cookie::new(self.cookie_name.clone(), "");
        cookie.set_http_only(self.http_only);
        cookie.set_secure(self.secure);
        cookie.set_same_site(self.same_site);
        cookie.set_path("/");
        cookie.set_max_age(cookie::time::Duration::seconds(0));

        response
            .headers_mut()
            .insert("set-cookie", cookie.to_string().parse().unwrap());

        Ok(response)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store.cleanup_expired().await
    }
}

/// Session middleware for automatic session handling
pub struct SessionMiddleware {
    manager: Arc<SessionManager>,
}

impl SessionMiddleware {
    pub fn new(manager: Arc<SessionManager>) -> Self {
        Self { manager }
    }
}

impl Middleware for SessionMiddleware {
    fn before(
        &self,
        mut req: Request<Body>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>,
    > {
        let manager = self.manager.clone();
        Box::pin(async move {
            // Load session from cookies and attach to request extensions
            match manager.get_session(&req).await {
                Ok(Some(session)) => {
                    req.extensions_mut().insert(session);
                }
                Ok(None) => {
                    // No session found, continue without session
                }
                Err(_) => {
                    // Session loading failed, continue without session
                    // In production, you might want to log this error
                }
            }

            Ok(req)
        })
    }
}

/// Helper functions for working with sessions in request handlers
pub mod helpers {
    use super::*;
    use hyper::Request;

    /// Get session from request extensions
    pub fn get_session(req: &Request<Body>) -> Option<&SessionData> {
        req.extensions().get::<SessionData>()
    }

    /// Get mutable session from request extensions
    pub fn get_session_mut(req: &mut Request<Body>) -> Option<&mut SessionData> {
        req.extensions_mut().get_mut::<SessionData>()
    }

    /// Create a new session for the request
    pub async fn create_session(
        manager: &SessionManager,
        req: &mut Request<Body>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = manager.create_session().await?;
        req.extensions_mut().insert(session);
        Ok(())
    }
}
