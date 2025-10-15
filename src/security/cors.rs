//! CORS (Cross-Origin Resource Sharing) Handling

use super::{SecurityError, SecurityEvent, SecurityMiddleware, SecurityResult};
use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};
use std::sync::Arc;

/// CORS configuration
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins (use "*" for all)
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Allow credentials
    pub allow_credentials: bool,
    /// Max age for preflight cache
    pub max_age: Option<u64>,
    /// Expose headers
    pub expose_headers: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
                "PATCH".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            allow_credentials: false,
            max_age: Some(86400), // 24 hours
            expose_headers: Vec::new(),
        }
    }
}

/// CORS middleware
pub struct CorsMiddleware {
    config: CorsConfig,
}

#[allow(dead_code)]
impl CorsMiddleware {
    /// Create a new CORS middleware with default config
    pub fn new() -> Self {
        Self {
            config: CorsConfig::default(),
        }
    }

    /// Create a new CORS middleware with custom config
    pub fn with_config(config: CorsConfig) -> Self {
        Self { config }
    }

    /// Check if origin is allowed
    fn is_origin_allowed(&self, origin: &str) -> bool {
        self.config.allowed_origins.contains(&"*".to_string())
            || self.config.allowed_origins.contains(&origin.to_string())
    }

    /// Check if method is allowed
    fn is_method_allowed(&self, method: &str) -> bool {
        self.config.allowed_methods.contains(&method.to_string())
    }

    /// Check if header is allowed
    fn is_header_allowed(&self, header: &str) -> bool {
        self.config.allowed_headers.contains(&header.to_string())
    }

    /// Handle preflight OPTIONS request
    fn handle_preflight(&self, request: &Request<Body>) -> SecurityResult<Response<Body>> {
        let origin = request.headers().get("origin");
        let request_method = request.headers().get("access-control-request-method");
        let request_headers = request.headers().get("access-control-request-headers");

        // Validate origin
        if let Some(origin_value) = origin {
            if let Ok(origin_str) = origin_value.to_str() {
                if !self.is_origin_allowed(origin_str) {
                    return Err(SecurityError::CorsViolation(format!(
                        "Origin '{}' not allowed",
                        origin_str
                    )));
                }
            }
        }

        // Validate request method
        if let Some(method_value) = request_method {
            if let Ok(method_str) = method_value.to_str() {
                if !self.is_method_allowed(method_str) {
                    return Err(SecurityError::CorsViolation(format!(
                        "Method '{}' not allowed",
                        method_str
                    )));
                }
            }
        }

        // Validate request headers
        if let Some(headers_value) = request_headers {
            if let Ok(headers_str) = headers_value.to_str() {
                for header in headers_str.split(',') {
                    let header = header.trim();
                    if !self.is_header_allowed(header) {
                        return Err(SecurityError::CorsViolation(format!(
                            "Header '{}' not allowed",
                            header
                        )));
                    }
                }
            }
        }

        // Create preflight response
        let mut response = Response::builder().status(200).body(Body::empty()).unwrap();

        // Add CORS headers
        if let Some(origin) = origin {
            response
                .headers_mut()
                .insert("Access-Control-Allow-Origin", origin.clone());
        }

        let allowed_methods = self.config.allowed_methods.join(", ");
        response.headers_mut().insert(
            "Access-Control-Allow-Methods",
            allowed_methods.parse().unwrap(),
        );

        let allowed_headers = self.config.allowed_headers.join(", ");
        response.headers_mut().insert(
            "Access-Control-Allow-Headers",
            allowed_headers.parse().unwrap(),
        );

        if self.config.allow_credentials {
            response
                .headers_mut()
                .insert("Access-Control-Allow-Credentials", "true".parse().unwrap());
        }

        if let Some(max_age) = self.config.max_age {
            response.headers_mut().insert(
                "Access-Control-Max-Age",
                max_age.to_string().parse().unwrap(),
            );
        }

        Ok(response)
    }

    /// Add CORS headers to response
    fn add_cors_headers(&self, response: &mut Response<Body>, request: &Request<Body>) {
        // Add origin
        if let Some(origin) = request.headers().get("origin") {
            if let Ok(origin_str) = origin.to_str() {
                if self.is_origin_allowed(origin_str) {
                    response
                        .headers_mut()
                        .insert("Access-Control-Allow-Origin", origin.clone());
                }
            }
        }

        // Add credentials
        if self.config.allow_credentials {
            response
                .headers_mut()
                .insert("Access-Control-Allow-Credentials", "true".parse().unwrap());
        }

        // Add expose headers
        if !self.config.expose_headers.is_empty() {
            let expose_headers = self.config.expose_headers.join(", ");
            response.headers_mut().insert(
                "Access-Control-Expose-Headers",
                expose_headers.parse().unwrap(),
            );
        }
    }
}

#[async_trait]
impl SecurityMiddleware for CorsMiddleware {
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Handle preflight OPTIONS request
        if request.method() == Method::OPTIONS {
            // This would normally return a response, but since we're in middleware,
            // we'll let the router handle it. In a real implementation, you'd need
            // to modify the middleware trait to allow returning responses.
            return Ok(request);
        }

        // For non-preflight requests, validate origin
        if let Some(origin) = request.headers().get("origin") {
            if let Ok(origin_str) = origin.to_str() {
                if !self.is_origin_allowed(origin_str) {
                    // Log CORS violation
                    let event = SecurityEvent::CorsViolation {
                        origin: Some(origin_str.to_string()),
                        method: request.method().to_string(),
                        headers: request
                            .headers()
                            .keys()
                            .map(|k| k.as_str().to_string())
                            .collect(),
                        timestamp: chrono::Utc::now(),
                    };
                    event_logger.log_event(event).await;

                    return Err(SecurityError::CorsViolation(format!(
                        "Origin '{}' not allowed",
                        origin_str
                    )));
                }
            }
        }

        Ok(request)
    }
}

/// CORS response processor (adds headers to responses)
pub struct CorsResponseProcessor {
    config: CorsConfig,
}

impl CorsResponseProcessor {
    /// Create a new CORS response processor
    pub fn new(config: CorsConfig) -> Self {
        Self { config }
    }

    /// Process response to add CORS headers
    pub fn process_response(
        &self,
        mut response: Response<Body>,
        request: &Request<Body>,
    ) -> Response<Body> {
        // Add CORS headers
        if let Some(origin) = request.headers().get("origin") {
            if let Ok(origin_str) = origin.to_str() {
                if self.config.allowed_origins.contains(&"*".to_string())
                    || self
                        .config
                        .allowed_origins
                        .contains(&origin_str.to_string())
                {
                    response
                        .headers_mut()
                        .insert("Access-Control-Allow-Origin", origin.clone());
                }
            }
        }

        if self.config.allow_credentials {
            response
                .headers_mut()
                .insert("Access-Control-Allow-Credentials", "true".parse().unwrap());
        }

        if !self.config.expose_headers.is_empty() {
            let expose_headers = self.config.expose_headers.join(", ");
            response.headers_mut().insert(
                "Access-Control-Expose-Headers",
                expose_headers.parse().unwrap(),
            );
        }

        response
    }
}

/// Dynamic CORS configuration based on request
pub struct DynamicCorsMiddleware<F> {
    config_fn: F,
}

impl<F> DynamicCorsMiddleware<F>
where
    F: Fn(&Request<Body>) -> CorsConfig + Send + Sync,
{
    /// Create a new dynamic CORS middleware
    pub fn new(config_fn: F) -> Self {
        Self { config_fn }
    }
}

#[async_trait]
impl<F> SecurityMiddleware for DynamicCorsMiddleware<F>
where
    F: Fn(&Request<Body>) -> CorsConfig + Send + Sync,
{
    async fn process(
        &self,
        request: Request<Body>,
        event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        let config = (self.config_fn)(&request);
        let cors_middleware = CorsMiddleware::with_config(config);
        cors_middleware.process(request, event_logger).await
    }
}

/// CORS configuration builder
pub struct CorsConfigBuilder {
    config: CorsConfig,
}

impl CorsConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: CorsConfig::default(),
        }
    }

    /// Set allowed origins
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config.allowed_origins = origins;
        self
    }

    /// Set allowed methods
    pub fn allowed_methods(mut self, methods: Vec<String>) -> Self {
        self.config.allowed_methods = methods;
        self
    }

    /// Set allowed headers
    pub fn allowed_headers(mut self, headers: Vec<String>) -> Self {
        self.config.allowed_headers = headers;
        self
    }

    /// Set allow credentials
    pub fn allow_credentials(mut self, allow: bool) -> Self {
        self.config.allow_credentials = allow;
        self
    }

    /// Set max age
    pub fn max_age(mut self, max_age: Option<u64>) -> Self {
        self.config.max_age = max_age;
        self
    }

    /// Set expose headers
    pub fn expose_headers(mut self, headers: Vec<String>) -> Self {
        self.config.expose_headers = headers;
        self
    }

    /// Build the configuration
    pub fn build(self) -> CorsConfig {
        self.config
    }
}

impl Default for CorsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
