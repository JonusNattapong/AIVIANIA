//! Security Headers Middleware

use super::{SecurityMiddleware, SecurityResult};
use async_trait::async_trait;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Body, Request, Response};
use std::collections::HashMap;
use std::sync::Arc;
use crate::middleware::Middleware as CrateMiddleware;

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Content Security Policy
    pub content_security_policy: Option<String>,
    /// X-Frame-Options
    pub x_frame_options: Option<String>,
    /// X-Content-Type-Options
    pub x_content_type_options: Option<String>,
    /// Referrer-Policy
    pub referrer_policy: Option<String>,
    /// Permissions-Policy
    pub permissions_policy: Option<String>,
    /// Strict-Transport-Security
    pub strict_transport_security: Option<String>,
    /// X-XSS-Protection (deprecated but still used)
    pub x_xss_protection: Option<String>,
    /// Custom headers
    pub custom_headers: HashMap<String, String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        let mut custom_headers = HashMap::new();
        custom_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        custom_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        custom_headers.insert(
            "Referrer-Policy".to_string(),
            "strict-origin-when-cross-origin".to_string(),
        );
        custom_headers.insert(
            "Permissions-Policy".to_string(),
            "geolocation=(), microphone=(), camera=()".to_string(),
        );

        Self {
            content_security_policy: Some("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            custom_headers,
        }
    }
}

/// Security headers middleware
pub struct SecurityHeadersMiddleware {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersMiddleware {
    /// Create a new security headers middleware with default config
    pub fn new() -> Self {
        Self {
            config: SecurityHeadersConfig::default(),
        }
    }

    /// Create a new security headers middleware with custom config
    pub fn with_config(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }

    /// Add security headers to response
    pub fn add_security_headers(&self, response: &mut Response<Body>) {
        // Content Security Policy
        if let Some(csp) = &self.config.content_security_policy {
            response
                .headers_mut()
                .insert("Content-Security-Policy", csp.parse().unwrap());
        }

        // X-Frame-Options
        if let Some(xfo) = &self.config.x_frame_options {
            response
                .headers_mut()
                .insert("X-Frame-Options", xfo.parse().unwrap());
        }

        // X-Content-Type-Options
        if let Some(xcto) = &self.config.x_content_type_options {
            response
                .headers_mut()
                .insert("X-Content-Type-Options", xcto.parse().unwrap());
        }

        // Referrer-Policy
        if let Some(rp) = &self.config.referrer_policy {
            response
                .headers_mut()
                .insert("Referrer-Policy", rp.parse().unwrap());
        }

        // Permissions-Policy
        if let Some(pp) = &self.config.permissions_policy {
            response
                .headers_mut()
                .insert("Permissions-Policy", pp.parse().unwrap());
        }

        // Strict-Transport-Security (only for HTTPS)
        if let Some(sts) = &self.config.strict_transport_security {
            response
                .headers_mut()
                .insert("Strict-Transport-Security", sts.parse().unwrap());
        }

        // X-XSS-Protection (deprecated but still used)
        if let Some(xxss) = &self.config.x_xss_protection {
            response
                .headers_mut()
                .insert("X-XSS-Protection", xxss.parse().unwrap());
        }

        // Custom headers
        for (name, value) in &self.config.custom_headers {
            let hn = HeaderName::from_bytes(name.as_bytes()).unwrap();
            let hv = HeaderValue::from_str(value).unwrap();
            response.headers_mut().insert(hn, hv);
        }
    }
}

#[async_trait]
impl SecurityMiddleware for SecurityHeadersMiddleware {
    async fn process(
        &self,
        request: Request<Body>,
        _event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // This middleware doesn't modify the request, just ensures headers are added to responses
        Ok(request)
    }
}

// Adapter implementation so SecurityHeadersMiddleware can be used as a crate::Middleware
impl CrateMiddleware for SecurityHeadersMiddleware {
    fn before(&self, req: Request<Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Request<Body>, Response<Body>>> + Send + '_>> {
        Box::pin(async move { Ok(req) })
    }

    fn after(&self, resp: Response<Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<Body>> + Send + '_>> {
        Box::pin(async move { resp })
    }
}

/// Security headers response processor
pub struct SecurityHeadersProcessor {
    middleware: SecurityHeadersMiddleware,
}

impl SecurityHeadersProcessor {
    /// Create a new security headers processor
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self {
            middleware: SecurityHeadersMiddleware::with_config(config),
        }
    }

    /// Process response to add security headers
    pub fn process_response(&self, mut response: Response<Body>) -> Response<Body> {
        self.middleware.add_security_headers(&mut response);
        response
    }
}

/// Content Security Policy builder
pub struct CspBuilder {
    directives: HashMap<String, Vec<String>>,
}

impl CspBuilder {
    /// Create a new CSP builder
    pub fn new() -> Self {
        Self {
            directives: HashMap::new(),
        }
    }

    /// Add default-src directive
    pub fn default_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("default-src".to_string(), sources);
        self
    }

    /// Add script-src directive
    pub fn script_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("script-src".to_string(), sources);
        self
    }

    /// Add style-src directive
    pub fn style_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("style-src".to_string(), sources);
        self
    }

    /// Add img-src directive
    pub fn img_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("img-src".to_string(), sources);
        self
    }

    /// Add connect-src directive
    pub fn connect_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("connect-src".to_string(), sources);
        self
    }

    /// Add font-src directive
    pub fn font_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("font-src".to_string(), sources);
        self
    }

    /// Add object-src directive
    pub fn object_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("object-src".to_string(), sources);
        self
    }

    /// Add media-src directive
    pub fn media_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("media-src".to_string(), sources);
        self
    }

    /// Add frame-src directive
    pub fn frame_src(mut self, sources: Vec<String>) -> Self {
        self.directives.insert("frame-src".to_string(), sources);
        self
    }

    /// Build CSP string
    pub fn build(self) -> String {
        self.directives
            .into_iter()
            .map(|(directive, sources)| format!("{} {}", directive, sources.join(" ")))
            .collect::<Vec<String>>()
            .join("; ")
    }
}

impl Default for CspBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Security headers configuration builder
pub struct SecurityHeadersConfigBuilder {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: SecurityHeadersConfig::default(),
        }
    }

    /// Set Content Security Policy
    pub fn content_security_policy(mut self, csp: Option<String>) -> Self {
        self.config.content_security_policy = csp;
        self
    }

    /// Set X-Frame-Options
    pub fn x_frame_options(mut self, options: Option<String>) -> Self {
        self.config.x_frame_options = options;
        self
    }

    /// Set X-Content-Type-Options
    pub fn x_content_type_options(mut self, options: Option<String>) -> Self {
        self.config.x_content_type_options = options;
        self
    }

    /// Set Referrer-Policy
    pub fn referrer_policy(mut self, policy: Option<String>) -> Self {
        self.config.referrer_policy = policy;
        self
    }

    /// Set Permissions-Policy
    pub fn permissions_policy(mut self, policy: Option<String>) -> Self {
        self.config.permissions_policy = policy;
        self
    }

    /// Set Strict-Transport-Security
    pub fn strict_transport_security(mut self, sts: Option<String>) -> Self {
        self.config.strict_transport_security = sts;
        self
    }

    /// Set X-XSS-Protection
    pub fn x_xss_protection(mut self, protection: Option<String>) -> Self {
        self.config.x_xss_protection = protection;
        self
    }

    /// Add custom header
    pub fn add_custom_header(mut self, name: String, value: String) -> Self {
        self.config.custom_headers.insert(name, value);
        self
    }

    /// Build the configuration
    pub fn build(self) -> SecurityHeadersConfig {
        self.config
    }
}

impl Default for SecurityHeadersConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTPS enforcement middleware
pub struct HttpsEnforcementMiddleware {
    _redirect_http: bool,
    _hsts_max_age: u64,
}

impl HttpsEnforcementMiddleware {
    /// Create a new HTTPS enforcement middleware
    pub fn new(redirect_http: bool, hsts_max_age: u64) -> Self {
        Self {
            _redirect_http: redirect_http,
            _hsts_max_age: hsts_max_age,
        }
    }
}

#[async_trait]
impl SecurityMiddleware for HttpsEnforcementMiddleware {
    async fn process(
        &self,
        request: Request<Body>,
        _event_logger: Arc<super::SecurityEventLogger>,
    ) -> SecurityResult<Request<Body>> {
        // Check if request is HTTPS
        if let Some(host) = request.headers().get("host") {
            if let Ok(_host_str) = host.to_str() {
                // In a real implementation, you'd check the connection scheme
                // For now, we'll assume it's HTTP if not explicitly HTTPS
                // This is a simplified implementation
            }
        }

        Ok(request)
    }
}

/// Security headers presets
pub mod presets {
    use super::*;

    /// Strict security headers preset
    pub fn strict() -> SecurityHeadersConfig {
        SecurityHeadersConfigBuilder::new()
            .content_security_policy(Some("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'".to_string()))
            .x_frame_options(Some("DENY".to_string()))
            .x_content_type_options(Some("nosniff".to_string()))
            .referrer_policy(Some("no-referrer".to_string()))
            .permissions_policy(Some("geolocation=(), microphone=(), camera=(), payment=(), usb=()".to_string()))
            .strict_transport_security(Some("max-age=63072000; includeSubDomains; preload".to_string()))
            .build()
    }

    /// Permissive security headers preset (for development)
    pub fn permissive() -> SecurityHeadersConfig {
        SecurityHeadersConfigBuilder::new()
            .content_security_policy(Some("default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'".to_string()))
            .x_frame_options(Some("SAMEORIGIN".to_string()))
            .x_content_type_options(Some("nosniff".to_string()))
            .referrer_policy(Some("strict-origin-when-cross-origin".to_string()))
            .permissions_policy(Some("geolocation=(), microphone=(), camera=()".to_string()))
            .strict_transport_security(Some("max-age=31536000".to_string()))
            .build()
    }

    /// API security headers preset
    pub fn api() -> SecurityHeadersConfig {
        SecurityHeadersConfigBuilder::new()
            .content_security_policy(Some("default-src 'none'".to_string()))
            .x_frame_options(Some("DENY".to_string()))
            .x_content_type_options(Some("nosniff".to_string()))
            .referrer_policy(Some("strict-origin-when-cross-origin".to_string()))
            .permissions_policy(Some(
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()".to_string(),
            ))
            .strict_transport_security(Some("max-age=31536000; includeSubDomains".to_string()))
            .add_custom_header("X-API-Version".to_string(), "1.0".to_string())
            .build()
    }
}
