use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Instant, Duration};

/// Simple token-bucket rate limiter (per-key) in-memory implementation.
pub struct RateLimiter {
    capacity: usize,
    refill_interval: Duration,
    buckets: Arc<Mutex<std::collections::HashMap<String, (usize, Instant)>>> ,
}

impl RateLimiter {
    pub fn new(capacity: usize, refill_interval: Duration) -> Self {
        Self { capacity, refill_interval, buckets: Arc::new(Mutex::new(std::collections::HashMap::new())) }
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
