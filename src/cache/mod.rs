//! # Caching Module
//!
//! Provides a flexible caching layer with multiple backend support including
//! in-memory and Redis caching. Features include:
//!
//! - Multiple cache backends (Memory, Redis)
//! - TTL (Time To Live) support
//! - Cache middleware for HTTP requests
//! - Async operations
//! - Serialization support for complex types

pub mod backends;
pub mod middleware;
pub mod config;

pub use backends::*;
pub use middleware::*;
pub use config::*;

/// Result type for cache operations
pub type CacheResult<T> = Result<T, CacheError>;

/// Cache operation errors
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis connection error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Cache key not found")]
    KeyNotFound,

    #[error("Backend not available")]
    BackendUnavailable,

    #[error("Invalid TTL value")]
    InvalidTtl,
}

/// Cache backend trait
#[async_trait::async_trait]
pub trait CacheBackend: Send + Sync {
    /// Get a value from cache
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>>;

    /// Set a value in cache with optional TTL
    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<u64>) -> CacheResult<()>;

    /// Delete a value from cache
    async fn delete(&self, key: &str) -> CacheResult<bool>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> CacheResult<bool>;

    /// Clear all cache entries
    async fn clear(&self) -> CacheResult<()>;

    /// Get cache statistics
    async fn stats(&self) -> CacheResult<CacheStats>;
}

/// Cache statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub sets: u64,
    pub deletes: u64,
    pub total_keys: u64,
}

/// Cache manager for handling multiple backends
pub struct CacheManager {
    backend: Box<dyn CacheBackend>,
}

impl CacheManager {
    /// Create a new cache manager with the specified backend
    pub fn new(backend: Box<dyn CacheBackend>) -> Self {
        Self { backend }
    }

    /// Get a value from cache
    pub async fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> CacheResult<Option<T>> {
        match self.backend.get(key).await? {
            Some(data) => {
                let value = serde_json::from_slice(&data)
                    .map_err(|e| CacheError::Deserialization(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Set a value in cache with optional TTL
    pub async fn set<T: serde::Serialize>(&self, key: &str, value: &T, ttl: Option<u64>) -> CacheResult<()> {
        let data = serde_json::to_vec(value)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;
        self.backend.set(key, data, ttl).await
    }

    /// Delete a value from cache
    pub async fn delete(&self, key: &str) -> CacheResult<bool> {
        self.backend.delete(key).await
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
        self.backend.exists(key).await
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> CacheResult<()> {
        self.backend.clear().await
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheResult<CacheStats> {
        self.backend.stats().await
    }
}