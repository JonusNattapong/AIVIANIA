//! Request module - Wrapper around hyper's Request.
//!
//! This module provides a Request type alias and helpers for hyper's Request.

use hyper::{Body, Request};

// Type alias for convenience
pub type AivianiaRequest = Request<Body>;
