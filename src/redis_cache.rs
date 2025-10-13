#![cfg(feature = "redis")]
use redis::AsyncCommands;
use std::sync::Arc;

pub struct RedisCache {
    client: redis::Client,
}

impl RedisCache {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }

    pub async fn set(&self, key: &str, value: &[u8], ttl_secs: usize) -> redis::RedisResult<()> {
        let mut conn = self.client.get_async_connection().await?;
        conn.set_ex(key, value, ttl_secs).await
    }

    pub async fn get(&self, key: &str) -> redis::RedisResult<Option<Vec<u8>>> {
        let mut conn = self.client.get_async_connection().await?;
        conn.get(key).await
    }
}
