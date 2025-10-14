//! Cache backends implementation

use super::{CacheBackend, CacheError, CacheResult, CacheStats};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory cache backend
pub struct MemoryCache {
    data: Arc<RwLock<HashMap<String, (Vec<u8>, Option<std::time::Instant>)>>>,
    stats: Arc<RwLock<CacheStats>>,
}

impl MemoryCache {
    /// Create a new in-memory cache
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats {
                hits: 0,
                misses: 0,
                sets: 0,
                deletes: 0,
                total_keys: 0,
            })),
        }
    }

    /// Clean expired entries
    async fn cleanup_expired(&self) {
        let mut data = self.data.write().await;
        let now = std::time::Instant::now();
        data.retain(|_, (_, expiry)| expiry.map_or(true, |exp| exp > now));
    }
}

#[async_trait]
impl CacheBackend for MemoryCache {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.cleanup_expired().await;
        let mut stats = self.stats.write().await;
        let data = self.data.read().await;

        match data.get(key) {
            Some((value, expiry)) => {
                if expiry.map_or(true, |exp| exp > std::time::Instant::now()) {
                    stats.hits += 1;
                    Ok(Some(value.clone()))
                } else {
                    stats.misses += 1;
                    Ok(None)
                }
            }
            None => {
                stats.misses += 1;
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<u64>) -> CacheResult<()> {
        let mut stats = self.stats.write().await;
        let mut data = self.data.write().await;

        let expiry = ttl.map(|t| std::time::Instant::now() + std::time::Duration::from_secs(t));
        data.insert(key.to_string(), (value, expiry));
        stats.sets += 1;
        stats.total_keys = data.len() as u64;

        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<bool> {
        let mut stats = self.stats.write().await;
        let mut data = self.data.write().await;

        let existed = data.remove(key).is_some();
        if existed {
            stats.deletes += 1;
            stats.total_keys = data.len() as u64;
        }

        Ok(existed)
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        self.cleanup_expired().await;
        let data = self.data.read().await;
        Ok(data.contains_key(key))
    }

    async fn clear(&self) -> CacheResult<()> {
        let mut stats = self.stats.write().await;
        let mut data = self.data.write().await;

        data.clear();
        stats.total_keys = 0;

        Ok(())
    }

    async fn stats(&self) -> CacheResult<CacheStats> {
        let stats = self.stats.read().await;
        Ok((*stats).clone())
    }
}

/// Redis cache backend
#[cfg(feature = "redis")]
pub struct RedisCache {
    client: redis::Client,
    stats: Arc<RwLock<CacheStats>>,
}

#[cfg(feature = "redis")]
impl RedisCache {
    /// Create a new Redis cache with connection URL
    pub fn new(url: &str) -> CacheResult<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            client,
            stats: Arc::new(RwLock::new(CacheStats {
                hits: 0,
                misses: 0,
                sets: 0,
                deletes: 0,
                total_keys: 0,
            })),
        })
    }

    /// Get async connection
    async fn get_connection(&self) -> CacheResult<redis::aio::Connection> {
        let conn = self.client.get_async_connection().await?;
        Ok(conn)
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl CacheBackend for RedisCache {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        let mut conn = self.get_connection().await?;
        let result: Option<Vec<u8>> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;

        let mut stats = self.stats.write().await;
        match result {
            Some(data) => {
                stats.hits += 1;
                Ok(Some(data))
            }
            None => {
                stats.misses += 1;
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<u64>) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;
        let mut cmd = redis::cmd("SET").arg(key).arg(value);

        if let Some(ttl_secs) = ttl {
            cmd = cmd.arg("EX").arg(ttl_secs);
        }

        let _: () = cmd.query_async(&mut conn).await?;

        let mut stats = self.stats.write().await;
        stats.sets += 1;

        // Update total keys count (approximate)
        let count: u64 = redis::cmd("DBSIZE").query_async(&mut conn).await?;
        stats.total_keys = count;

        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<bool> {
        let mut conn = self.get_connection().await?;
        let deleted: u64 = redis::cmd("DEL").arg(key).query_async(&mut conn).await?;

        let mut stats = self.stats.write().await;
        if deleted > 0 {
            stats.deletes += 1;
            // Update total keys count
            let count: u64 = redis::cmd("DBSIZE").query_async(&mut conn).await?;
            stats.total_keys = count;
        }

        Ok(deleted > 0)
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        let mut conn = self.get_connection().await?;
        let exists: u64 = redis::cmd("EXISTS").arg(key).query_async(&mut conn).await?;
        Ok(exists > 0)
    }

    async fn clear(&self) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await?;

        let mut stats = self.stats.write().await;
        stats.total_keys = 0;

        Ok(())
    }

    async fn stats(&self) -> CacheResult<CacheStats> {
        let mut conn = self.get_connection().await?;
        let count: u64 = redis::cmd("DBSIZE").query_async(&mut conn).await?;

        let mut stats = self.stats.write().await;
        stats.total_keys = count;

        Ok((*stats).clone())
    }
}

/// Cache backend types
pub enum CacheBackendType {
    Memory,
    #[cfg(feature = "redis")]
    Redis(String), // Redis URL
}

/// Create a cache backend from type
pub fn create_backend(backend_type: CacheBackendType) -> Box<dyn CacheBackend> {
    match backend_type {
        CacheBackendType::Memory => Box::new(MemoryCache::new()),
        #[cfg(feature = "redis")]
        CacheBackendType::Redis(url) => Box::new(RedisCache::new(&url).expect("Failed to create Redis cache")),
    }
}