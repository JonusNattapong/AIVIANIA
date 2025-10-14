//! Cache middleware for HTTP requests

use super::{CacheManager, CacheResult};
use crate::middleware::{Middleware, MiddlewareResult};
use crate::request::Request;
use crate::response::Response;
use async_trait::async_trait;
use std::collections::HashMap;

/// Cache configuration for middleware
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Cache key prefix
    pub key_prefix: String,
    /// Default TTL in seconds
    pub default_ttl: Option<u64>,
    /// Cache only GET requests
    pub cache_get_only: bool,
    /// Headers to include in cache key
    pub key_headers: Vec<String>,
    /// Headers to exclude from cached response
    pub exclude_headers: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            key_prefix: "http_cache".to_string(),
            default_ttl: Some(300), // 5 minutes
            cache_get_only: true,
            key_headers: vec!["accept".to_string(), "accept-language".to_string()],
            exclude_headers: vec![
                "date".to_string(),
                "server".to_string(),
                "x-cache".to_string(),
                "x-cache-hit".to_string(),
            ],
        }
    }
}

/// Cached response data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    cached_at: chrono::DateTime<chrono::Utc>,
}

/// HTTP cache middleware
pub struct CacheMiddleware {
    cache: CacheManager,
    config: CacheConfig,
}

impl CacheMiddleware {
    /// Create a new cache middleware
    pub fn new(cache: CacheManager, config: CacheConfig) -> Self {
        Self { cache, config }
    }

    /// Generate cache key from request
    fn generate_cache_key(&self, request: &Request) -> String {
        let mut key_parts = vec![self.config.key_prefix.clone()];

        // Add method
        if !self.config.cache_get_only {
            key_parts.push(request.method().to_string());
        }

        // Add path
        key_parts.push(request.uri().path().to_string());

        // Add query parameters
        if let Some(query) = request.uri().query() {
            key_parts.push(query.to_string());
        }

        // Add selected headers
        for header_name in &self.config.key_headers {
            if let Some(value) = request.headers().get(header_name) {
                if let Ok(value_str) = value.to_str() {
                    key_parts.push(format!("{}:{}", header_name, value_str));
                }
            }
        }

        // Create final key
        key_parts.join("|")
    }

    /// Check if request should be cached
    fn should_cache_request(&self, request: &Request) -> bool {
        // Only cache GET requests if configured
        if self.config.cache_get_only && request.method() != "GET" {
            return false;
        }

        // Don't cache requests with authorization headers
        if request.headers().contains_key("authorization") {
            return false;
        }

        true
    }

    /// Check if response should be cached
    fn should_cache_response(&self, response: &Response) -> bool {
        // Only cache successful responses
        response.status().is_success()
    }

    /// Extract response data for caching
    fn extract_response_data(&self, response: &Response) -> CachedResponse {
        let mut headers = HashMap::new();

        for (name, value) in response.headers() {
            let name_str = name.as_str();
            if !self.config.exclude_headers.contains(&name_str.to_lowercase()) {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name_str.to_string(), value_str.to_string());
                }
            }
        }

        CachedResponse {
            status: response.status().as_u16(),
            headers,
            body: response.body().clone(),
            cached_at: chrono::Utc::now(),
        }
    }

    /// Create response from cached data
    fn create_response_from_cache(&self, cached: &CachedResponse) -> Response {
        let mut response = Response::builder()
            .status(cached.status)
            .body(cached.body.clone())
            .unwrap();

        // Add cached headers
        for (name, value) in &cached.headers {
            response.headers_mut().insert(
                name.parse().unwrap(),
                value.parse().unwrap(),
            );
        }

        // Add cache metadata headers
        response.headers_mut().insert(
            "x-cache",
            "HIT".parse().unwrap(),
        );

        response.headers_mut().insert(
            "x-cache-time",
            cached.cached_at.to_rfc3339().parse().unwrap(),
        );

        response
    }
}

#[async_trait]
impl Middleware for CacheMiddleware {
    async fn process(&self, request: Request, next: crate::middleware::Next) -> MiddlewareResult {
        // Check if request should be cached
        if !self.should_cache_request(&request) {
            return next.run(request).await;
        }

        let cache_key = self.generate_cache_key(&request);

        // Try to get from cache first
        if let Ok(Some(cached_response)) = self.cache.get::<CachedResponse>(&cache_key).await {
            let response = self.create_response_from_cache(&cached_response);
            return Ok(response);
        }

        // Process request
        let response = next.run(request).await?;

        // Cache response if appropriate
        if self.should_cache_response(&response) {
            let cached_data = self.extract_response_data(&response);
            let ttl = self.config.default_ttl;

            // Cache in background (don't block response)
            let cache = self.cache.clone();
            let key = cache_key.clone();
            tokio::spawn(async move {
                let _ = cache.set(&key, &cached_data, ttl).await;
            });
        }

        // Add cache miss header
        let mut response = response;
        response.headers_mut().insert(
            "x-cache",
            "MISS".parse().unwrap(),
        );

        Ok(response)
    }
}

/// Cache control middleware for manual cache management
pub struct CacheControlMiddleware {
    cache: CacheManager,
}

impl CacheControlMiddleware {
    /// Create a new cache control middleware
    pub fn new(cache: CacheManager) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl Middleware for CacheControlMiddleware {
    async fn process(&self, request: Request, next: crate::middleware::Next) -> MiddlewareResult {
        let response = next.run(request).await?;

        // Handle cache control headers
        if let Some(cache_control) = response.headers().get("cache-control") {
            if let Ok(value) = cache_control.to_str() {
                if value.contains("no-cache") || value.contains("no-store") {
                    // Don't cache this response
                    return Ok(response);
                }
            }
        }

        Ok(response)
    }
}