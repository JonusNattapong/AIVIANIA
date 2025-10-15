//! Security Configuration

use super::*;

/// Security configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityConfig {
    pub csrf: CsrfConfig,
    pub cors: CorsConfig,
    pub headers: SecurityHeadersConfig,
    pub validation: ValidationConfig,
    pub rate_limiting: RateLimitingConfig,
    pub logging: LoggingConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            csrf: CsrfConfig::default(),
            cors: CorsConfig::default(),
            headers: SecurityHeadersConfig::default(),
            validation: ValidationConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl SecurityConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            csrf: CsrfConfig::from_env()?,
            cors: CorsConfig::from_env()?,
            headers: SecurityHeadersConfig::from_env()?,
            validation: ValidationConfig::from_env()?,
            rate_limiting: RateLimitingConfig::from_env()?,
            logging: LoggingConfig::from_env()?,
        })
    }

    /// Load configuration from file
    pub async fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, SecurityError> {
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            SecurityError::ConfigError(format!("Failed to read config file: {}", e))
        })?;

        serde_json::from_str(&content)
            .map_err(|e| SecurityError::ConfigError(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to file
    pub async fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<(), SecurityError> {
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            SecurityError::ConfigError(format!("Failed to serialize config: {}", e))
        })?;

        tokio::fs::write(path, content)
            .await
            .map_err(|e| SecurityError::ConfigError(format!("Failed to write config file: {}", e)))
    }
}

/// CSRF configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsrfConfig {
    pub enabled: bool,
    pub token_name: String,
    pub cookie_name: String,
    pub header_name: String,
    pub token_length: usize,
    pub token_lifetime: u64, // seconds
    pub secure_cookie: bool,
    pub http_only_cookie: bool,
    pub same_site: SameSitePolicy,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            token_name: "csrf_token".to_string(),
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            token_length: 32,
            token_lifetime: 3600, // 1 hour
            secure_cookie: true,
            http_only_cookie: true,
            same_site: SameSitePolicy::Strict,
        }
    }
}

impl CsrfConfig {
    fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            enabled: std::env::var("AIVIANIA_CSRF_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CSRF_ENABLED value".to_string())
                })?,
            token_name: std::env::var("AIVIANIA_CSRF_TOKEN_NAME")
                .unwrap_or_else(|_| "csrf_token".to_string()),
            cookie_name: std::env::var("AIVIANIA_CSRF_COOKIE_NAME")
                .unwrap_or_else(|_| "csrf_token".to_string()),
            header_name: std::env::var("AIVIANIA_CSRF_HEADER_NAME")
                .unwrap_or_else(|_| "X-CSRF-Token".to_string()),
            token_length: std::env::var("AIVIANIA_CSRF_TOKEN_LENGTH")
                .unwrap_or_else(|_| "32".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CSRF_TOKEN_LENGTH value".to_string())
                })?,
            token_lifetime: std::env::var("AIVIANIA_CSRF_TOKEN_LIFETIME")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CSRF_TOKEN_LIFETIME value".to_string())
                })?,
            secure_cookie: std::env::var("AIVIANIA_CSRF_SECURE_COOKIE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CSRF_SECURE_COOKIE value".to_string())
                })?,
            http_only_cookie: std::env::var("AIVIANIA_CSRF_HTTP_ONLY_COOKIE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CSRF_HTTP_ONLY_COOKIE value".to_string())
                })?,
            same_site: std::env::var("AIVIANIA_CSRF_SAME_SITE")
                .unwrap_or_else(|_| "strict".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CSRF_SAME_SITE value".to_string())
                })?,
        })
    }
}

/// Same site policy
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
}

impl std::str::FromStr for SameSitePolicy {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "lax" => Ok(Self::Lax),
            "none" => Ok(Self::None),
            _ => Err(SecurityError::ConfigError(format!(
                "Invalid same site policy: {}",
                s
            ))),
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<u32>,
    pub preflight_cache_duration: u64, // seconds
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age: Some(86400),           // 24 hours
            preflight_cache_duration: 3600, // 1 hour
        }
    }
}

impl CorsConfig {
    fn from_env() -> Result<Self, SecurityError> {
        let allowed_origins = std::env::var("AIVIANIA_CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let allowed_methods = std::env::var("AIVIANIA_CORS_ALLOWED_METHODS")
            .unwrap_or_else(|_| "GET,POST,PUT,DELETE,OPTIONS".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let allowed_headers = std::env::var("AIVIANIA_CORS_ALLOWED_HEADERS")
            .unwrap_or_else(|_| "Content-Type,Authorization,X-Requested-With".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Self {
            enabled: std::env::var("AIVIANIA_CORS_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CORS_ENABLED value".to_string())
                })?,
            allowed_origins,
            allowed_methods,
            allowed_headers,
            exposed_headers: vec![], // Not configurable via env yet
            allow_credentials: std::env::var("AIVIANIA_CORS_ALLOW_CREDENTIALS")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CORS_ALLOW_CREDENTIALS value".to_string())
                })?,
            max_age: std::env::var("AIVIANIA_CORS_MAX_AGE")
                .ok()
                .map(|s| s.parse())
                .transpose()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid CORS_MAX_AGE value".to_string())
                })?,
            preflight_cache_duration: std::env::var("AIVIANIA_CORS_PREFLIGHT_CACHE_DURATION")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError(
                        "Invalid CORS_PREFLIGHT_CACHE_DURATION value".to_string(),
                    )
                })?,
        })
    }
}

/// Security headers configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityHeadersConfig {
    pub enabled: bool,
    pub preset: SecurityHeadersPreset,
    pub custom_headers: HashMap<String, String>,
    pub csp_directives: HashMap<String, Vec<String>>,
    pub hsts_max_age: u32,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preset: SecurityHeadersPreset::Strict,
            custom_headers: HashMap::new(),
            csp_directives: HashMap::new(),
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: false,
        }
    }
}

impl SecurityHeadersConfig {
    fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            enabled: std::env::var("AIVIANIA_HEADERS_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid HEADERS_ENABLED value".to_string())
                })?,
            preset: std::env::var("AIVIANIA_HEADERS_PRESET")
                .unwrap_or_else(|_| "strict".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid HEADERS_PRESET value".to_string())
                })?,
            custom_headers: HashMap::new(), // Not configurable via env yet
            csp_directives: HashMap::new(), // Not configurable via env yet
            hsts_max_age: std::env::var("AIVIANIA_HSTS_MAX_AGE")
                .unwrap_or_else(|_| "31536000".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid HSTS_MAX_AGE value".to_string())
                })?,
            hsts_include_subdomains: std::env::var("AIVIANIA_HSTS_INCLUDE_SUBDOMAINS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid HSTS_INCLUDE_SUBDOMAINS value".to_string())
                })?,
            hsts_preload: std::env::var("AIVIANIA_HSTS_PRELOAD")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid HSTS_PRELOAD value".to_string())
                })?,
        })
    }
}

/// Security headers preset
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SecurityHeadersPreset {
    Strict,
    Permissive,
    Api,
    Custom,
}

impl std::str::FromStr for SecurityHeadersPreset {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "permissive" => Ok(Self::Permissive),
            "api" => Ok(Self::Api),
            "custom" => Ok(Self::Custom),
            _ => Err(SecurityError::ConfigError(format!(
                "Invalid security headers preset: {}",
                s
            ))),
        }
    }
}

/// Validation configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidationConfig {
    pub enabled: bool,
    pub max_field_length: usize,
    pub max_file_size: usize, // bytes
    pub allowed_file_types: Vec<String>,
    pub sanitize_html: bool,
    pub sql_injection_protection: bool,
    pub xss_protection: bool,
    pub custom_rules: HashMap<String, String>, // field -> regex pattern
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_field_length: 10000,
            max_file_size: 10 * 1024 * 1024, // 10MB
            allowed_file_types: vec![
                "image/jpeg".to_string(),
                "image/png".to_string(),
                "image/gif".to_string(),
                "application/pdf".to_string(),
                "text/plain".to_string(),
            ],
            sanitize_html: true,
            sql_injection_protection: true,
            xss_protection: true,
            custom_rules: HashMap::new(),
        }
    }
}

impl ValidationConfig {
    fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            enabled: std::env::var("AIVIANIA_VALIDATION_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid VALIDATION_ENABLED value".to_string())
                })?,
            max_field_length: std::env::var("AIVIANIA_VALIDATION_MAX_FIELD_LENGTH")
                .unwrap_or_else(|_| "10000".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError(
                        "Invalid VALIDATION_MAX_FIELD_LENGTH value".to_string(),
                    )
                })?,
            max_file_size: std::env::var("AIVIANIA_VALIDATION_MAX_FILE_SIZE")
                .unwrap_or_else(|_| "10485760".to_string()) // 10MB
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid VALIDATION_MAX_FILE_SIZE value".to_string())
                })?,
            allowed_file_types: std::env::var("AIVIANIA_VALIDATION_ALLOWED_FILE_TYPES")
                .unwrap_or_else(|_| {
                    "image/jpeg,image/png,image/gif,application/pdf,text/plain".to_string()
                })
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            sanitize_html: std::env::var("AIVIANIA_VALIDATION_SANITIZE_HTML")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid VALIDATION_SANITIZE_HTML value".to_string())
                })?,
            sql_injection_protection: std::env::var("AIVIANIA_VALIDATION_SQL_INJECTION_PROTECTION")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError(
                        "Invalid VALIDATION_SQL_INJECTION_PROTECTION value".to_string(),
                    )
                })?,
            xss_protection: std::env::var("AIVIANIA_VALIDATION_XSS_PROTECTION")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError(
                        "Invalid VALIDATION_XSS_PROTECTION value".to_string(),
                    )
                })?,
            custom_rules: HashMap::new(), // Not configurable via env yet
        })
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_limit: u32,
    pub block_duration: u64,    // seconds
    pub whitelist: Vec<String>, // IP addresses
    pub blacklist: Vec<String>, // IP addresses
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            burst_limit: 10,
            block_duration: 300, // 5 minutes
            whitelist: vec![],
            blacklist: vec![],
        }
    }
}

impl RateLimitingConfig {
    fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            enabled: std::env::var("AIVIANIA_RATE_LIMIT_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid RATE_LIMIT_ENABLED value".to_string())
                })?,
            requests_per_minute: std::env::var("AIVIANIA_RATE_LIMIT_REQUESTS_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError(
                        "Invalid RATE_LIMIT_REQUESTS_PER_MINUTE value".to_string(),
                    )
                })?,
            burst_limit: std::env::var("AIVIANIA_RATE_LIMIT_BURST_LIMIT")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid RATE_LIMIT_BURST_LIMIT value".to_string())
                })?,
            block_duration: std::env::var("AIVIANIA_RATE_LIMIT_BLOCK_DURATION")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError(
                        "Invalid RATE_LIMIT_BLOCK_DURATION value".to_string(),
                    )
                })?,
            whitelist: std::env::var("AIVIANIA_RATE_LIMIT_WHITELIST")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            blacklist: std::env::var("AIVIANIA_RATE_LIMIT_BLACKLIST")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }
}

/// Logging configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub level: LogLevel,
    pub format: LogFormat,
    pub file_path: Option<String>,
    pub max_file_size: u64, // bytes
    pub max_files: usize,
    pub console_output: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: LogLevel::Info,
            format: LogFormat::Json,
            file_path: Some("security.log".to_string()),
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
            console_output: true,
        }
    }
}

impl LoggingConfig {
    fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            enabled: std::env::var("AIVIANIA_LOG_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| SecurityError::ConfigError("Invalid LOG_ENABLED value".to_string()))?,
            level: std::env::var("AIVIANIA_LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string())
                .parse()
                .map_err(|_| SecurityError::ConfigError("Invalid LOG_LEVEL value".to_string()))?,
            format: std::env::var("AIVIANIA_LOG_FORMAT")
                .unwrap_or_else(|_| "json".to_string())
                .parse()
                .map_err(|_| SecurityError::ConfigError("Invalid LOG_FORMAT value".to_string()))?,
            file_path: std::env::var("AIVIANIA_LOG_FILE_PATH").ok(),
            max_file_size: std::env::var("AIVIANIA_LOG_MAX_FILE_SIZE")
                .unwrap_or_else(|_| "10485760".to_string()) // 10MB
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid LOG_MAX_FILE_SIZE value".to_string())
                })?,
            max_files: std::env::var("AIVIANIA_LOG_MAX_FILES")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid LOG_MAX_FILES value".to_string())
                })?,
            console_output: std::env::var("AIVIANIA_LOG_CONSOLE_OUTPUT")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| {
                    SecurityError::ConfigError("Invalid LOG_CONSOLE_OUTPUT value".to_string())
                })?,
        })
    }
}

/// Log level
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::str::FromStr for LogLevel {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(SecurityError::ConfigError(format!(
                "Invalid log level: {}",
                s
            ))),
        }
    }
}

/// Log format
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LogFormat {
    Json,
    Text,
}

impl std::str::FromStr for LogFormat {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            _ => Err(SecurityError::ConfigError(format!(
                "Invalid log format: {}",
                s
            ))),
        }
    }
}
