use hyper::{Body, Request};
use bytes::Bytes;
use std::convert::Infallible;
use futures_util::TryStreamExt;

/// Buffer the entire request body up to `max_bytes`. Returns None if the body is larger than limit.
pub async fn buffer_request_body(mut req: Request<Body>, max_bytes: usize) -> Result<(Request<Body>, Option<Bytes>), Infallible> {
    let mut collected = Vec::new();
    let mut stream = req.into_body();

    while let Some(chunk) = stream.try_next().await.unwrap_or(None) {
        collected.extend_from_slice(&chunk);
        if collected.len() > max_bytes {
            // Drop remaining and return None to indicate limit exceeded
            return Ok((Request::new(Body::empty()), None));
        }
    }

    let bytes = Bytes::from(collected);
    // Recreate the request with buffered body so downstream can read it
    let mut new_req = Request::new(Body::from(bytes.clone()));
    *new_req.method_mut() = req.method().clone();
    *new_req.uri_mut() = req.uri().clone();
    *new_req.headers_mut() = req.headers().clone();

    Ok((new_req, Some(bytes)))
}
