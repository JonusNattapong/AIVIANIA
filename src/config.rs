//! Configuration module - Environment and file-based configuration management.
//!
//! This module provides configuration loading from environment variables,
//! YAML/TOML files, and command-line arguments.

use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File};

/// Main application configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub websocket: WebSocketConfig,
    pub logging: LoggingConfig,
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
    pub connection_timeout: Option<u64>,
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub bcrypt_cost: Option<u32>,
}

/// WebSocket configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    pub max_connections: Option<usize>,
    pub heartbeat_interval: Option<u64>,
    pub max_message_size: Option<usize>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
                workers: Some(4),
            },
            database: DatabaseConfig {
                url: "sqlite:aiviania.db".to_string(),
                max_connections: Some(10),
                connection_timeout: Some(30),
            },
            auth: AuthConfig {
                jwt_secret: "default-secret-key-change-in-production".to_string(),
                jwt_expiration_hours: 24,
                bcrypt_cost: Some(12),
            },
            websocket: WebSocketConfig {
                max_connections: Some(1000),
                heartbeat_interval: Some(30),
                max_message_size: Some(65536),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
        }
    }
}

impl AppConfig {
    /// Load configuration from multiple sources with priority:
    /// 1. Environment variables (highest priority)
    /// 2. Configuration file (YAML/TOML)
    /// 3. Default values (lowest priority)
    pub fn load() -> Result<Self, ConfigError> {
        let mut builder = Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("AIVIANIA").separator("_"));

        // Try to load from config.yml or config.toml if they exist
        if std::path::Path::new("config.yml").exists() {
            builder = builder.add_source(File::with_name("config"));
        } else if std::path::Path::new("config.toml").exists() {
            builder = builder.add_source(File::with_name("config"));
        }

        // Load .env file if it exists
        if std::path::Path::new(".env").exists() {
            dotenvy::dotenv().ok();
        }

        let config = builder.build()?;
        config.try_deserialize()
    }

    /// Load configuration with custom file path.
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let builder = Config::builder()
            .add_source(File::from(path.as_ref()))
            .add_source(config::Environment::with_prefix("AIVIANIA").separator("_"));

        if std::path::Path::new(".env").exists() {
            dotenvy::dotenv().ok();
        }

        let config = builder.build()?;
        config.try_deserialize()
    }

    /// Get server bind address.
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.auth.jwt_secret.len() < 32 {
            return Err("JWT secret must be at least 32 characters long".to_string());
        }

        if self.server.port == 0 {
            return Err("Server port cannot be 0".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.url, "sqlite:aiviania.db");
        assert_eq!(config.auth.jwt_expiration_hours, 24);
    }

    #[test]
    fn test_config_validation() {
        let mut config = AppConfig::default();
        assert!(config.validate().is_ok());

        config.auth.jwt_secret = "short".to_string();
        assert!(config.validate().is_err());

        config = AppConfig::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_addr() {
        let config = AppConfig::default();
        assert_eq!(config.server_addr(), "127.0.0.1:3000");
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yml");

        let yaml_content = r#"
server:
  host: "0.0.0.0"
  port: 8080
database:
  url: "sqlite:test.db"
auth:
  jwt_secret: "super-secret-key-that-is-long-enough-for-testing"
  jwt_expiration_hours: 24
websocket:
  max_connections: 1000
logging:
  level: "info"
  format: "json"
"#;

        fs::write(&config_path, yaml_content).unwrap();

        let config = AppConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.url, "sqlite:test.db");
    }
}