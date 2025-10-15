//! Input Validation and Sanitization

use super::{SecurityError, SecurityEvent, SecurityMiddleware, SecurityResult};
use async_trait::async_trait;
use hyper::{Body, Request};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

/// Validation rule
#[derive(Debug, Clone)]
pub enum ValidationRule {
    /// Required field
    Required,
    /// Minimum length
    MinLength(usize),
    /// Maximum length
    MaxLength(usize),
    /// Exact length
    Length(usize),
    /// Regular expression pattern
    Pattern(String),
    /// Email format
    Email,
    /// URL format
    Url,
    /// Numeric range
    Range(i64, i64),
    /// Custom validation function
    Custom(String), // Function name for custom validators
}

/// Input validator
pub struct InputValidator {
    rules: HashMap<String, Vec<ValidationRule>>,
    custom_validators: HashMap<String, Box<dyn Fn(&str) -> bool + Send + Sync>>,
}

impl InputValidator {
    /// Create a new input validator
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            custom_validators: HashMap::new(),
        }
    }

    /// Add validation rule for a field
    pub fn add_rule(mut self, field: String, rule: ValidationRule) -> Self {
        self.rules.entry(field).or_insert_with(Vec::new).push(rule);
        self
    }

    /// Add multiple rules for a field
    pub fn add_rules(mut self, field: String, rules: Vec<ValidationRule>) -> Self {
        self.rules
            .entry(field)
            .or_insert_with(Vec::new)
            .extend(rules);
        self
    }

    /// Add custom validator function
    pub fn add_custom_validator<F>(mut self, name: String, validator: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.custom_validators.insert(name, Box::new(validator));
        self
    }

    /// Validate input data
    pub fn validate(&self, data: &serde_json::Value) -> SecurityResult<()> {
        let mut errors = Vec::new();

        for (field, rules) in &self.rules {
            let field_value = data.get(field);

            for rule in rules {
                if let Err(error) = self.validate_rule(field, field_value, rule) {
                    errors.push(error);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(SecurityError::Validation(format!(
                "Validation failed: {:?}",
                errors
            )))
        }
    }

    /// Validate a single rule
    fn validate_rule(
        &self,
        field: &str,
        value: Option<&serde_json::Value>,
        rule: &ValidationRule,
    ) -> SecurityResult<()> {
        match rule {
            ValidationRule::Required => {
                if value.is_none() || value.unwrap().is_null() {
                    return Err(SecurityError::Validation(format!(
                        "Field '{}' is required",
                        field
                    )));
                }
            }
            ValidationRule::MinLength(min) => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        if s.len() < *min {
                            return Err(SecurityError::Validation(format!(
                                "Field '{}' must be at least {} characters",
                                field, min
                            )));
                        }
                    }
                }
            }
            ValidationRule::MaxLength(max) => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        if s.len() > *max {
                            return Err(SecurityError::Validation(format!(
                                "Field '{}' must be at most {} characters",
                                field, max
                            )));
                        }
                    }
                }
            }
            ValidationRule::Length(len) => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        if s.len() != *len {
                            return Err(SecurityError::Validation(format!(
                                "Field '{}' must be exactly {} characters",
                                field, len
                            )));
                        }
                    }
                }
            }
            ValidationRule::Pattern(pattern) => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        if let Ok(regex) = Regex::new(pattern) {
                            if !regex.is_match(s) {
                                return Err(SecurityError::Validation(format!(
                                    "Field '{}' does not match pattern '{}'",
                                    field, pattern
                                )));
                            }
                        }
                    }
                }
            }
            ValidationRule::Email => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        let email_regex = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
                        if !email_regex.is_match(s) {
                            return Err(SecurityError::Validation(format!(
                                "Field '{}' is not a valid email address",
                                field
                            )));
                        }
                    }
                }
            }
            ValidationRule::Url => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        if url::Url::parse(s).is_err() {
                            return Err(SecurityError::Validation(format!(
                                "Field '{}' is not a valid URL",
                                field
                            )));
                        }
                    }
                }
            }
            ValidationRule::Range(min, max) => {
                if let Some(val) = value {
                    if let Some(num) = val.as_i64() {
                        if num < *min || num > *max {
                            return Err(SecurityError::Validation(format!(
                                "Field '{}' must be between {} and {}",
                                field, min, max
                            )));
                        }
                    }
                }
            }
            ValidationRule::Custom(validator_name) => {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        if let Some(validator) = self.custom_validators.get(validator_name) {
                            if !validator(s) {
                                return Err(SecurityError::Validation(format!(
                                    "Field '{}' failed custom validation '{}'",
                                    field, validator_name
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Sanitize input data
    pub fn sanitize(&self, data: &mut serde_json::Value) {
        self.sanitize_value(data);
    }

    /// Sanitize a JSON value
    fn sanitize_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                *s = self.sanitize_string(s);
            }
            serde_json::Value::Object(obj) => {
                for (_, v) in obj.iter_mut() {
                    self.sanitize_value(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.sanitize_value(item);
                }
            }
            _ => {} // Other types don't need sanitization
        }
    }

    /// Sanitize a string value
    fn sanitize_string(&self, input: &str) -> String {
        // Basic HTML sanitization - remove script tags and dangerous attributes
        let script_regex = Regex::new(r"<script[^>]*>.*?</script>").unwrap();
        let mut result = script_regex.replace_all(input, "").to_string();

        // Remove dangerous attributes
        let dangerous_attrs = Regex::new(r#"(on\w+|javascript:|vbscript:|data:)"#).unwrap();
        result = dangerous_attrs.replace_all(&result, "").to_string();

        // Trim whitespace
        result.trim().to_string()
    }
}

/// Input validation middleware
pub struct InputValidationMiddleware {
    validator: InputValidator,
    sanitize_input: bool,
}

impl InputValidationMiddleware {
    /// Create a new input validation middleware
    pub fn new(validator: InputValidator, sanitize_input: bool) -> Self {
        Self {
            validator,
            sanitize_input,
        }
    }

    /// Extract JSON data from request
    fn extract_json_data(&self, request: &Request<Body>) -> Option<serde_json::Value> {
        // Avoid consuming request body in middleware. Parse query string instead.
        if let Some(query) = request.uri().query() {
            let mut map: HashMap<String, String> = HashMap::new();
            for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                map.insert(k.into_owned(), v.into_owned());
            }
            if !map.is_empty() {
                return serde_json::to_value(map).ok();
            }
        }

        None
    }
}

#[async_trait]
impl SecurityMiddleware for InputValidationMiddleware {
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Extract data from request
        if let Some(mut data) = self.extract_json_data(&request) {
            // Sanitize input if enabled
            if self.sanitize_input {
                self.validator.sanitize(&mut data);
            }

            // Validate input
            if let Err(validation_error) = self.validator.validate(&data) {
                // Log validation failure
                let event = SecurityEvent::InputValidationFailure {
                    field: "request_body".to_string(), // Could be more specific
                    rule: "general".to_string(),
                    value: None,
                    timestamp: chrono::Utc::now(),
                };
                event_logger.log_event(event).await;

                return Err(validation_error);
            }
        }

        Ok(request)
    }
}

/// SQL injection prevention
pub struct SqlInjectionPrevention {
    patterns: Vec<Regex>,
}

impl SqlInjectionPrevention {
    /// Create a new SQL injection prevention middleware
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set|drop\s+table|alter\s+table|--|#|/\*|\*/|;|')").unwrap(),
        ];

        Self { patterns }
    }

    /// Check for SQL injection patterns
    pub fn check_sql_injection(&self, input: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(input))
    }
}

#[async_trait]
impl SecurityMiddleware for SqlInjectionPrevention {
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Check query parameters via parsing the query string (avoid consuming body)
        if let Some(q) = request.uri().query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                if self.check_sql_injection(&v) {
                    let event = SecurityEvent::SuspiciousActivity {
                        ip: "unknown".to_string(),
                        activity: format!("SQL injection attempt in query param '{}'", k),
                        severity: super::SecuritySeverity::High,
                        timestamp: chrono::Utc::now(),
                    };
                    event_logger.log_event(event).await;

                    return Err(SecurityError::PolicyViolation(
                        "Potential SQL injection detected".to_string(),
                    ));
                }
            }
        }

        Ok(request)
    }
}

/// XSS (Cross-Site Scripting) prevention
pub struct XssPrevention {
    patterns: Vec<Regex>,
}

impl XssPrevention {
    /// Create a new XSS prevention middleware
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"<script[^>]*>.*?</script>").unwrap(),
            Regex::new(r"javascript:").unwrap(),
            Regex::new(r"vbscript:").unwrap(),
            Regex::new(r"on\w+\s*=").unwrap(),
        ];

        Self { patterns }
    }

    /// Check for XSS patterns
    pub fn check_xss(&self, input: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(input))
    }
}

#[async_trait]
impl SecurityMiddleware for XssPrevention {
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Check query parameters via parsing
        if let Some(q) = request.uri().query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                if self.check_xss(&v) {
                    let event = SecurityEvent::SuspiciousActivity {
                        ip: "unknown".to_string(),
                        activity: format!("XSS attempt in query param '{}'", k),
                        severity: super::SecuritySeverity::Medium,
                        timestamp: chrono::Utc::now(),
                    };
                    event_logger.log_event(event).await;

                    return Err(SecurityError::PolicyViolation(
                        "Potential XSS attack detected".to_string(),
                    ));
                }
            }
        }

        // Body checks are skipped in middleware to avoid consuming the request body.

        Ok(request)
    }
}

/// Validation rule builder for fluent API
pub struct ValidationRuleBuilder {
    rules: Vec<ValidationRule>,
}

impl ValidationRuleBuilder {
    /// Create a new rule builder
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add required rule
    pub fn required(mut self) -> Self {
        self.rules.push(ValidationRule::Required);
        self
    }

    /// Add minimum length rule
    pub fn min_length(mut self, len: usize) -> Self {
        self.rules.push(ValidationRule::MinLength(len));
        self
    }

    /// Add maximum length rule
    pub fn max_length(mut self, len: usize) -> Self {
        self.rules.push(ValidationRule::MaxLength(len));
        self
    }

    /// Add exact length rule
    pub fn length(mut self, len: usize) -> Self {
        self.rules.push(ValidationRule::Length(len));
        self
    }

    /// Add pattern rule
    pub fn pattern(mut self, pattern: String) -> Self {
        self.rules.push(ValidationRule::Pattern(pattern));
        self
    }

    /// Add email rule
    pub fn email(mut self) -> Self {
        self.rules.push(ValidationRule::Email);
        self
    }

    /// Add URL rule
    pub fn url(mut self) -> Self {
        self.rules.push(ValidationRule::Url);
        self
    }

    /// Add range rule
    pub fn range(mut self, min: i64, max: i64) -> Self {
        self.rules.push(ValidationRule::Range(min, max));
        self
    }

    /// Add custom rule
    pub fn custom(mut self, validator: String) -> Self {
        self.rules.push(ValidationRule::Custom(validator));
        self
    }

    /// Build the rules
    pub fn build(self) -> Vec<ValidationRule> {
        self.rules
    }
}

impl Default for ValidationRuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_and_min_length() {
        let validator = InputValidator::new()
            .add_rule("name".to_string(), ValidationRule::Required)
            .add_rule("name".to_string(), ValidationRule::MinLength(3));

        let good = serde_json::json!({ "name": "John" });
        assert!(validator.validate(&good).is_ok());

        let bad = serde_json::json!({ "name": "Al" });
        assert!(validator.validate(&bad).is_err());
    }

    #[test]
    fn test_sanitize_removes_script() {
        let validator = InputValidator::new();
        let mut data = serde_json::json!({ "bio": "Hello <script>alert(1)</script> world" });
        validator.sanitize(&mut data);
        let bio = data.get("bio").and_then(|v| v.as_str()).unwrap();
        assert!(!bio.contains("script"));
    }
}
