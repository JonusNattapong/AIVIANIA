use prometheus::{Encoder, TextEncoder, Registry, IntCounterVec, HistogramVec, opts, histogram_opts};
use once_cell::sync::Lazy;
use std::sync::Arc;

pub static REGISTRY: Lazy<Registry> = Lazy::new(|| Registry::new());

pub static HTTP_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(opts!("http_requests_total", "Total HTTP requests received"), &["method", "route", "status"]).unwrap();
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

pub static HTTP_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    let hist = HistogramVec::new(histogram_opts!("http_request_duration_seconds", "HTTP request latencies"), &["method", "route"]).unwrap();
    REGISTRY.register(Box::new(hist.clone())).ok();
    hist
});

/// Initialize tracing subscriber with env filter
pub fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();
}

/// Return metrics as text/plain for Prometheus
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    let mf = REGISTRY.gather();
    encoder.encode(&mf, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap_or_default()
}
