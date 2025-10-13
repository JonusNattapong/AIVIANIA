//! Response module - Helpers for creating responses.
//!
//! This module provides Response helpers for JSON, HTML, and custom responses.

use hyper::{Response, Body, StatusCode};
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
        self.headers.push(("Content-Type".to_string(), "application/json".to_string()));
        self.body = Body::from(json);
        self
    }

    /// Set HTML response.
    pub fn html(mut self, html: &str) -> Self {
        self.headers.push(("Content-Type".to_string(), "text/html".to_string()));
        self.body = Body::from(html.to_string());
        self
    }

    /// Add a header.
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }
}

impl From<AivianiaResponse> for Response<Body> {
    fn from(resp: AivianiaResponse) -> Self {
        let mut builder = Response::builder().status(resp.status);
        for (key, value) in resp.headers {
            builder = builder.header(key, value);
        }
        builder.body(resp.body).unwrap()
    }
}