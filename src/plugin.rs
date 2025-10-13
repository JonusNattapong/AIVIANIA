//! Plugin module - Extensible plugin system.
//!
//! This module provides a plugin system for adding AI modules, database adapters, etc.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Trait for plugins.
pub trait Plugin: Any + Send + Sync {
    /// Get plugin as Any for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Get plugin name.
    fn name(&self) -> &'static str;

    /// Initialize the plugin.
    fn init(&self) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        Box::pin(async { Ok(()) })
    }
}

/// Plugin manager.
#[derive(Clone)]
pub struct PluginManager {
    plugins: Arc<HashMap<String, Arc<Box<dyn Plugin>>>>,
}

impl PluginManager {
    /// Create a new plugin manager.
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(HashMap::new()),
        }
    }

    /// Add a plugin.
    pub fn add(&mut self, plugin: Box<dyn Plugin>) {
        let mut plugins = Arc::clone(&self.plugins);
        let plugins_mut = Arc::make_mut(&mut plugins);
        plugins_mut.insert(plugin.name().to_string(), Arc::new(plugin));
        self.plugins = plugins;
    }

    /// Get a plugin by name.
    pub fn get(&self, name: &str) -> Option<&Arc<Box<dyn Plugin>>> {
        self.plugins.get(name)
    }
}

// Example plugin: AI Plugin
pub struct AIPlugin {
    api_key: String,
}

impl AIPlugin {
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }

    /// Call AI API with the given prompt.
    pub fn call_ai(&self, prompt: &str) -> Pin<Box<dyn Future<Output = Result<String, Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        let prompt = prompt.to_string();
        let api_key = self.api_key.clone();
        Box::pin(async move {
            let client = reqwest::Client::new();
            let response = client
                .post("https://api.openai.com/v1/chat/completions")
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 150
                }))
                .send()
                .await?;

            let json: serde_json::Value = response.json().await?;
            if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
                if let Some(choice) = choices.get(0) {
                    if let Some(message) = choice.get("message").and_then(|m| m.get("content")) {
                        return Ok(message.as_str().unwrap_or("No response").to_string());
                    }
                }
            }
            Ok("No response from AI".to_string())
        })
    }
}

impl Plugin for AIPlugin {
    fn as_any(&self) -> &dyn Any { self }

    fn name(&self) -> &'static str {
        "ai"
    }

    fn init(&self) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        Box::pin(async {
            println!("Initializing AI Plugin");
            Ok(())
        })
    }
}