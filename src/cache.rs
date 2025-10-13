use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Very small in-memory cache for responses/sessions.
pub struct SimpleCache {
    inner: Mutex<HashMap<String, (Vec<u8>, Instant, Duration)>>,
}

impl SimpleCache {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn set(&self, key: &str, value: Vec<u8>, ttl: Duration) {
        let mut map = self.inner.lock().unwrap();
        map.insert(key.to_string(), (value, Instant::now(), ttl));
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut map = self.inner.lock().unwrap();
        if let Some((val, inserted, ttl)) = map.get(key) {
            if inserted.elapsed() < *ttl {
                return Some(val.clone());
            } else {
                map.remove(key);
            }
        }
        None
    }
}
