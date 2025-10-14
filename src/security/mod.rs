//! Advanced Security Module
//!
//! Provides comprehensive security features including:
//!
//! - CSRF (Cross-Site Request Forgery) protection
//! - CORS (Cross-Origin Resource Sharing) handling
//! - Security headers (HSTS, CSP, X-Frame-Options, etc.)
//! - Input validation and sanitization
//! - Rate limiting with security rules
//! - Authentication middleware enhancements
//! - Security event logging and monitoring

pub mod csrf;
pub mod cors;
pub mod headers;
pub mod validation;
pub mod events;
pub mod config;

pub use csrf::*;
pub use cors::*;
pub use headers::*;
pub use validation::*;
pub use events::*;
pub use config::{SecurityConfig, CsrfConfig, CorsConfig, SecurityHeadersConfig, ValidationConfig, RateLimitingConfig, LoggingConfig, SameSitePolicy, SecurityHeadersPreset, LogLevel, LogFormat};

/// Result type for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

/// Security operation errors
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("CSRF validation failed: {0}")]
    CsrfValidation(String),

    #[error("CORS policy violation: {0}")]
    CorsViolation(String),

    #[error("Input validation failed: {0}")]
    Validation(String),

    #[error("Security policy violation: {0}")]
    PolicyViolation(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Authorization failed: {0}")]
    Authorization(String),

    #[error("Security configuration error: {0}")]
    ConfigError(String),
}

/// Security event types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SecurityEvent {
    CsrfAttackAttempt {
        ip: String,
        user_agent: Option<String>,
        url: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    CorsViolation {
        origin: Option<String>,
        method: String,
        headers: Vec<String>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    InputValidationFailure {
        field: String,
        rule: String,
        value: Option<String>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    RateLimitExceeded {
        ip: String,
        endpoint: String,
        limit: u64,
        window_secs: u64,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    SuspiciousActivity {
        ip: String,
        activity: String,
        severity: SecuritySeverity,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

/// Security severity levels
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security event logger
pub struct SecurityEventLogger {
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    max_events: usize,
}

impl SecurityEventLogger {
    /// Create a new security event logger
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events,
        }
    }

    /// Log a security event
    pub async fn log_event(&self, event: SecurityEvent) {
        let mut events = self.events.write().await;

        // Add new event
        events.push(event);

        // Maintain max size by removing oldest events
        if events.len() > self.max_events {
            let overflow = events.len() - self.max_events;
            events.drain(0..overflow);
        }
    }

    /// Get recent events
    pub async fn get_recent_events(&self, limit: Option<usize>) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100);
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Get events by type
    pub async fn get_events_by_type(&self, event_type: &str) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        events.iter().filter(|event| {
            match event {
                SecurityEvent::CsrfAttackAttempt { .. } if event_type == "csrf" => true,
                SecurityEvent::CorsViolation { .. } if event_type == "cors" => true,
                SecurityEvent::InputValidationFailure { .. } if event_type == "validation" => true,
                SecurityEvent::RateLimitExceeded { .. } if event_type == "rate_limit" => true,
                SecurityEvent::SuspiciousActivity { .. } if event_type == "suspicious" => true,
                _ => false,
            }
        }).cloned().collect()
    }

    /// Clear all events
    pub async fn clear_events(&self) {
        let mut events = self.events.write().await;
        events.clear();
    }

    /// Get security statistics
    pub async fn get_stats(&self) -> serde_json::Value {
        let events = self.events.read().await;

        let mut stats = std::collections::HashMap::new();
        for event in events.iter() {
            let key = match event {
                SecurityEvent::CsrfAttackAttempt { .. } => "csrf_attempts",
                SecurityEvent::CorsViolation { .. } => "cors_violations",
                SecurityEvent::InputValidationFailure { .. } => "validation_failures",
                SecurityEvent::RateLimitExceeded { .. } => "rate_limit_exceeded",
                SecurityEvent::SuspiciousActivity { .. } => "suspicious_activities",
            };

            *stats.entry(key.to_string()).or_insert(0) += 1;
        }

        serde_json::json!({
            "total_events": events.len(),
            "stats": stats,
            "last_updated": chrono::Utc::now().to_rfc3339()
        })
    }
}

/// Security middleware stack
pub struct SecurityMiddlewareStack {
    middlewares: Vec<Box<dyn SecurityMiddleware>>,
    event_logger: Arc<SecurityEventLogger>,
}

impl SecurityMiddlewareStack {
    /// Create a new security middleware stack
    pub fn new(event_logger: Arc<SecurityEventLogger>) -> Self {
        Self {
            middlewares: Vec::new(),
            event_logger,
        }
    }

    /// Add a security middleware
    pub fn add_middleware<M: SecurityMiddleware + 'static>(&mut self, middleware: M) {
        self.middlewares.push(Box::new(middleware));
    }

    /// Process request through security middlewares
    pub async fn process(&self, request: hyper::Request<hyper::Body>) -> SecurityResult<hyper::Request<hyper::Body>> {
        let mut current_request = request;

        for middleware in &self.middlewares {
            current_request = middleware.process(current_request, self.event_logger.clone()).await?;
        }

        Ok(current_request)
    }
}

/// Security middleware trait
#[async_trait::async_trait]
pub trait SecurityMiddleware: Send + Sync {
    /// Process the request through security checks
    async fn process(
        &self,
        request: hyper::Request<hyper::Body>,
        event_logger: Arc<SecurityEventLogger>,
    ) -> SecurityResult<hyper::Request<hyper::Body>>;
}