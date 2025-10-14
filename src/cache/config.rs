//! Cache configuration

use super::backends::CacheBackendType;
use serde::{Deserialize, Serialize};

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache backend type
    pub backend: CacheBackend,

    /// Default TTL in seconds
    pub default_ttl: Option<u64>,

    /// Maximum cache size (for memory backend)
    pub max_size: Option<usize>,

    /// Cache key prefix
    pub key_prefix: String,

    /// Enable cache compression
    pub compression: bool,

    /// Cache statistics collection
    pub collect_stats: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::Memory,
            default_ttl: Some(300), // 5 minutes
            max_size: Some(1000),   // 1000 entries
            key_prefix: "aiviania_cache".to_string(),
            compression: false,
            collect_stats: true,
        }
    }
}

/// Cache backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheBackend {
    /// In-memory cache
    Memory,

    /// Redis cache
    Redis(RedisConfig),
}

/// Redis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,

    /// Connection pool size
    pub pool_size: Option<u32>,

    /// Database number
    pub database: Option<u8>,

    /// Password (optional)
    pub password: Option<String>,

    /// Connection timeout in seconds
    pub timeout: Option<u64>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            pool_size: Some(10),
            database: Some(0),
            password: None,
            timeout: Some(30),
        }
    }
}

/// Cache configuration builder
pub struct CacheConfigBuilder {
    config: CacheConfig,
}

impl CacheConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: CacheConfig::default(),
        }
    }

    /// Set cache backend
    pub fn backend(mut self, backend: CacheBackend) -> Self {
        self.config.backend = backend;
        self
    }

    /// Set default TTL
    pub fn default_ttl(mut self, ttl: Option<u64>) -> Self {
        self.config.default_ttl = ttl;
        self
    }

    /// Set maximum cache size
    pub fn max_size(mut self, size: Option<usize>) -> Self {
        self.config.max_size = size;
        self
    }

    /// Set key prefix
    pub fn key_prefix(mut self, prefix: String) -> Self {
        self.config.key_prefix = prefix;
        self
    }

    /// Enable/disable compression
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.compression = enabled;
        self
    }

    /// Enable/disable statistics collection
    pub fn collect_stats(mut self, enabled: bool) -> Self {
        self.config.collect_stats = enabled;
        self
    }

    /// Build the configuration
    pub fn build(self) -> CacheConfig {
        self.config
    }
}

impl Default for CacheConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Load cache configuration from environment variables
pub fn load_from_env() -> CacheConfig {
    let mut builder = CacheConfigBuilder::new();

    // Backend type
    if let Ok(backend_type) = std::env::var("CACHE_BACKEND") {
        match backend_type.to_lowercase().as_str() {
            "redis" => {
                let redis_config = RedisConfig {
                    url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
                    pool_size: std::env::var("REDIS_POOL_SIZE").ok().and_then(|s| s.parse().ok()),
                    database: std::env::var("REDIS_DATABASE").ok().and_then(|s| s.parse().ok()),
                    password: std::env::var("REDIS_PASSWORD").ok(),
                    timeout: std::env::var("REDIS_TIMEOUT").ok().and_then(|s| s.parse().ok()),
                };
                builder = builder.backend(CacheBackend::Redis(redis_config));
            }
            _ => {} // Default to memory
        }
    }

    // Other settings
    if let Ok(ttl) = std::env::var("CACHE_DEFAULT_TTL") {
        if let Ok(ttl_val) = ttl.parse::<u64>() {
            builder = builder.default_ttl(Some(ttl_val));
        }
    }

    if let Ok(size) = std::env::var("CACHE_MAX_SIZE") {
        if let Ok(size_val) = size.parse::<usize>() {
            builder = builder.max_size(Some(size_val));
        }
    }

    if let Ok(prefix) = std::env::var("CACHE_KEY_PREFIX") {
        builder = builder.key_prefix(prefix);
    }

    if let Ok(compression) = std::env::var("CACHE_COMPRESSION") {
        builder = builder.compression(compression.to_lowercase() == "true");
    }

    if let Ok(stats) = std::env::var("CACHE_COLLECT_STATS") {
        builder = builder.collect_stats(stats.to_lowercase() == "true");
    }

    builder.build()
}