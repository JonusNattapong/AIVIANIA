#![cfg(feature = "redis")]
use redis::AsyncCommands;
use std::time::Duration;
use std::sync::Arc;

pub struct RedisRateLimiter {
    client: redis::Client,
    capacity: usize,
    ttl: Duration,
}

impl RedisRateLimiter {
    pub fn new(client: redis::Client, capacity: usize, ttl: Duration) -> Self {
        Self { client, capacity, ttl }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let mut conn = match self.client.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let script = r#"
local v = redis.call('GET', KEYS[1])
if not v then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return 1
else
  local n = tonumber(v)
  if n < tonumber(ARGV[1]) then
    redis.call('INCR', KEYS[1])
    return 1
  end
  return 0
end
"#;
        let capacity = self.capacity as u64;
        let ttl_ms = self.ttl.as_millis() as u64;
        let res: redis::RedisResult<i32> = redis::Script::new(script).key(key).arg(capacity).arg(ttl_ms).invoke_async(&mut conn).await;
        match res {
            Ok(v) => v == 1,
            Err(_) => false,
        }
    }
}
