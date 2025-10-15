use crate::middleware::Middleware;
use crate::response::AivianiaResponse;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Simple token-bucket rate limiter (per-key) in-memory implementation.
pub struct RateLimiter {
    capacity: usize,
    refill_interval: Duration,
    buckets: Arc<Mutex<std::collections::HashMap<String, (usize, Instant)>>>,
}

impl RateLimiter {
    pub fn new(capacity: usize, refill_interval: Duration) -> Self {
        Self {
            capacity,
            refill_interval,
            buckets: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let mut map = self.buckets.lock().await;
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert((self.capacity, now));
        let (tokens, last) = entry.clone();
        let elapsed = now.duration_since(last);
        if elapsed >= self.refill_interval {
            *entry = (self.capacity, now);
            return true;
        }
        if tokens > 0 {
            entry.0 = tokens - 1;
            return true;
        }
        false
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per time window
    pub requests_per_window: usize,
    /// Time window duration
    pub window_duration: Duration,
    /// Key extraction strategy
    pub key_strategy: KeyStrategy,
    /// Whether to use Redis for distributed rate limiting
    pub use_redis: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,
            window_duration: Duration::from_secs(60), // 1 minute
            key_strategy: KeyStrategy::IP,
            use_redis: false,
        }
    }
}

/// Strategy for extracting rate limit keys
#[derive(Debug, Clone)]
pub enum KeyStrategy {
    /// Use client IP address
    IP,
    /// Use authenticated user ID
    User,
    /// Use custom header value
    Header(String),
    /// Use route path
    Path,
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    #[cfg(feature = "redis")]
    redis_limiter: Option<crate::redis_rate_limit::RedisRateLimiter>,
    memory_limiter: RateLimiter,
    config: RateLimitConfig,
}

impl RateLimitMiddleware {
    /// Create new rate limiting middleware
    pub fn new(config: RateLimitConfig) -> Self {
        let memory_limiter = RateLimiter::new(config.requests_per_window, config.window_duration);

        #[cfg(feature = "redis")]
        let redis_limiter = if config.use_redis {
            // Try to create Redis client from environment
            if let Ok(redis_url) = std::env::var("REDIS_URL") {
                if let Ok(client) = redis::Client::open(redis_url) {
                    Some(crate::redis_rate_limit::RedisRateLimiter::new(
                        client,
                        config.requests_per_window,
                        config.window_duration,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Self {
            #[cfg(feature = "redis")]
            redis_limiter,
            memory_limiter,
            config,
        }
    }

    /// Extract rate limit key from request
    fn extract_key(&self, req: &Request<Body>) -> String {
        match &self.config.key_strategy {
            KeyStrategy::IP => {
                // Extract IP from request (simplified - in production you'd use proper IP extraction)
                req.headers()
                    .get("x-forwarded-for")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("unknown")
                    .split(',')
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string()
            }
            KeyStrategy::User => {
                // Extract user ID from session or JWT (simplified)
                req.headers()
                    .get("authorization")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|auth| {
                        if auth.starts_with("Bearer ") {
                            Some(auth.trim_start_matches("Bearer "))
                        } else {
                            None
                        }
                    })
                    .unwrap_or("anonymous")
                    .to_string()
            }
            KeyStrategy::Header(header_name) => req
                .headers()
                .get(header_name)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown")
                .to_string(),
            KeyStrategy::Path => req.uri().path().to_string(),
        }
    }

    /// Check if request should be allowed
    async fn check_rate_limit(&self, key: &str) -> bool {
        #[cfg(feature = "redis")]
        if let Some(ref redis_limiter) = self.redis_limiter {
            return redis_limiter.allow(key).await;
        }

        self.memory_limiter.allow(key).await
    }
}

#[async_trait::async_trait]
impl Middleware for RateLimitMiddleware {
    fn before(
        &self,
        req: Request<Body>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>,
    > {
        let key = self.extract_key(&req);

        Box::pin(async move {
            if self.check_rate_limit(&key).await {
                Ok(req)
            } else {
                // Rate limit exceeded
                let response = AivianiaResponse::new(StatusCode::TOO_MANY_REQUESTS)
                    .header("retry-after", "60")
                    .json(&serde_json::json!({
                        "error": "Rate limit exceeded",
                        "message": "Too many requests. Please try again later.",
                        "retry_after": 60
                    }));

                Err(response.into())
            }
        })
    }
}

/// Builder for rate limiting middleware
pub struct RateLimitBuilder {
    config: RateLimitConfig,
}

impl RateLimitBuilder {
    pub fn new() -> Self {
        Self {
            config: RateLimitConfig::default(),
        }
    }

    pub fn requests_per_window(mut self, requests: usize) -> Self {
        self.config.requests_per_window = requests;
        self
    }

    pub fn window_duration(mut self, duration: Duration) -> Self {
        self.config.window_duration = duration;
        self
    }

    pub fn key_strategy(mut self, strategy: KeyStrategy) -> Self {
        self.config.key_strategy = strategy;
        self
    }

    pub fn use_redis(mut self, use_redis: bool) -> Self {
        self.config.use_redis = use_redis;
        self
    }

    pub fn build(self) -> RateLimitMiddleware {
        RateLimitMiddleware::new(self.config)
    }
}

impl Default for RateLimitBuilder {
    fn default() -> Self {
        Self::new()
    }
}
