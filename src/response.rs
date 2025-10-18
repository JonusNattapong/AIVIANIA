//! Response module - Helpers for creating responses.
//!
//! This module provides Response helpers for JSON, HTML, and custom responses.

use hyper::{Body, Response as HyperResponse, StatusCode};
use serde::Serialize;

/// Response wrapper with helpers.
pub struct AivianiaResponse {
    status: StatusCode,
    body: Body,
    headers: Vec<(String, String)>,
}

impl AivianiaResponse {
    /// Create a new response.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            body: Body::empty(),
            headers: Vec::new(),
        }
    }

    /// Set the response body.
    pub fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }

    /// Set JSON response.
    pub fn json<T: Serialize>(mut self, data: &T) -> Self {
        let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        self.body = Body::from(json);
        self
    }

    /// Set HTML response.
    pub fn html(mut self, html: &str) -> Self {
        self.headers
            .push(("Content-Type".to_string(), "text/html".to_string()));
        self.body = Body::from(html.to_string());
        self
    }

    /// Add a header.
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }
}

impl From<AivianiaResponse> for HyperResponse<Body> {
    fn from(resp: AivianiaResponse) -> Self {
        let mut builder = HyperResponse::builder().status(resp.status);
        for (key, value) in resp.headers {
            builder = builder.header(key, value);
        }
        builder.body(resp.body).unwrap()
    }
}

// Make a module-level alias so `aiviania::response::Response` resolves for examples
pub use AivianiaResponse as Response;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;
    use serde_json::json;

    #[test]
    fn test_new_response() {
        let resp = AivianiaResponse::new(StatusCode::OK);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.headers.len(), 0);
    }

    #[test]
    fn test_json_response() {
        let data = json!({"message": "hello", "status": "success"});
        let resp = AivianiaResponse::new(StatusCode::OK).json(&data);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(
            resp.headers[0],
            ("Content-Type".to_string(), "application/json".to_string())
        );

        // Convert to hyper response and check body
        let hyper_resp: HyperResponse<Body> = resp.into();
        assert_eq!(hyper_resp.status(), StatusCode::OK);
        assert_eq!(
            hyper_resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_html_response() {
        let html = "<h1>Hello World</h1>";
        let resp = AivianiaResponse::new(StatusCode::OK).html(html);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(
            resp.headers[0],
            ("Content-Type".to_string(), "text/html".to_string())
        );

        let hyper_resp: HyperResponse<Body> = resp.into();
        assert_eq!(hyper_resp.status(), StatusCode::OK);
        assert_eq!(
            hyper_resp.headers().get("content-type").unwrap(),
            "text/html"
        );
    }

    #[test]
    fn test_custom_headers() {
        let resp = AivianiaResponse::new(StatusCode::OK)
            .header("X-Custom", "value")
            .header("Authorization", "Bearer token");

        assert_eq!(resp.headers.len(), 2);
        assert!(resp
            .headers
            .contains(&("X-Custom".to_string(), "value".to_string())));
        assert!(resp
            .headers
            .contains(&("Authorization".to_string(), "Bearer token".to_string())));
    }

    #[test]
    fn test_body_method() {
        let body_content = "Custom body content";
        let resp = AivianiaResponse::new(StatusCode::OK).body(Body::from(body_content));

        let hyper_resp: HyperResponse<Body> = resp.into();
        assert_eq!(hyper_resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_into_hyper_response() {
        let resp = AivianiaResponse::new(StatusCode::NOT_FOUND)
            .header("X-Error", "Not Found")
            .json(&json!({"error": "Resource not found"}));

        let hyper_resp: HyperResponse<Body> = resp.into();
        assert_eq!(hyper_resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(hyper_resp.headers().get("x-error").unwrap(), "Not Found");
        assert_eq!(
            hyper_resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }
}
