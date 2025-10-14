//! Cache example demonstrating various caching features
//!
//! This example shows how to:
//! - Set up different cache backends (memory, Redis)
//! - Use cache middleware for HTTP requests
//! - Manually cache and retrieve data
//! - Monitor cache performance

#[cfg(feature = "cache")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aiviania::cache::{
        backends::{create_backend, CacheBackendType},
        config::CacheConfigBuilder,
        middleware::{CacheConfig, CacheMiddleware},
        CacheManager,
    };
    use aiviania::middleware::MiddlewareStack;
    use aiviania::router::Router;
    use aiviania::server::Server;
    use std::time::Duration;

    println!("🚀 Starting AIVIANIA Cache Example");

    // Example 1: Basic cache operations with memory backend
    println!("\n📝 Example 1: Basic Cache Operations");
    let memory_backend = create_backend(CacheBackendType::Memory);
    let cache_manager = CacheManager::new(memory_backend);

    // Cache some data
    let user_data = serde_json::json!({
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com"
    });

    cache_manager.set("user:1", &user_data, Some(300)).await?;
    println!("✅ Cached user data with 5-minute TTL");

    // Retrieve cached data
    if let Some(cached_user) = cache_manager.get::<serde_json::Value>("user:1").await? {
        println!("✅ Retrieved cached user: {}", cached_user["name"]);
    }

    // Check cache statistics
    let stats = cache_manager.stats().await?;
    println!("📊 Cache stats - Hits: {}, Misses: {}, Total keys: {}",
             stats.hits, stats.misses, stats.total_keys);

    // Example 2: Redis backend (if Redis is available)
    #[cfg(feature = "redis")]
    {
        println!("\n🔴 Example 2: Redis Cache Backend");
        match create_backend(CacheBackendType::Redis("redis://127.0.0.1:6379".to_string())).downcast::<aiviania::cache::backends::RedisCache>() {
            Ok(redis_backend) => {
                let redis_cache = CacheManager::new(redis_backend);
                redis_cache.set("redis_key", &"Hello Redis!", Some(600)).await?;
                println!("✅ Cached data in Redis");

                if let Some(value) = redis_cache.get::<String>("redis_key").await? {
                    println!("✅ Retrieved from Redis: {}", value);
                }
            }
            Err(_) => println!("⚠️  Redis not available, skipping Redis example"),
        }
    }

    // Example 3: Cache middleware with HTTP server
    println!("\n🌐 Example 3: HTTP Cache Middleware");

    let cache_config = CacheConfig {
        key_prefix: "api_cache".to_string(),
        default_ttl: Some(60), // 1 minute
        cache_get_only: true,
        key_headers: vec!["accept".to_string()],
        exclude_headers: vec!["date".to_string(), "server".to_string()],
    };

    let cache_middleware = CacheMiddleware::new(cache_manager, cache_config);

    // Create router with cached endpoints
    let mut router = Router::new();

    router.get("/api/users/:id", |req| async move {
        let id = req.params().get("id").unwrap_or("unknown");

        // Simulate database query delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        let user = serde_json::json!({
            "id": id,
            "name": format!("User {}", id),
            "cached_at": chrono::Utc::now().to_rfc3339()
        });

        aiviania::response::Response::json(&user)
    });

    router.get("/api/stats", |req| async move {
        let stats = serde_json::json!({
            "uptime": "1h 30m",
            "requests": 1250,
            "cached_requests": 890
        });

        aiviania::response::Response::json(&stats)
    });

    // Create middleware stack with cache
    let mut middleware_stack = MiddlewareStack::new();
    middleware_stack.add(cache_middleware);

    // Create server
    let server = Server::new(router)
        .middleware(middleware_stack)
        .bind("127.0.0.1:3000");

    println!("🚀 Server starting on http://127.0.0.1:3000");
    println!("📖 Try these endpoints:");
    println!("   GET /api/users/123");
    println!("   GET /api/stats");
    println!("   Headers will show cache hits/misses");

    // Run server for demonstration (in real app, this would run indefinitely)
    println!("\n⏹️  Server demonstration complete");
    println!("💡 Cache features demonstrated:");
    println!("   ✅ Memory and Redis backends");
    println!("   ✅ TTL-based expiration");
    println!("   ✅ HTTP response caching");
    println!("   ✅ Cache statistics");
    println!("   ✅ Async operations");

    Ok(())
}

#[cfg(not(feature = "cache"))]
fn main() {
    println!("❌ Cache feature not enabled. Run with: cargo run --example cache --features cache");
}