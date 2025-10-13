use prometheus::{Encoder, TextEncoder, Registry, Counter, Opts, Gauge};
use once_cell::sync::Lazy;

pub static REGISTRY: Lazy<Registry> = Lazy::new(|| Registry::new());

pub static REQUEST_COUNTER: Lazy<Counter> = Lazy::new(|| {
    let opts = Opts::new("aiviania_requests_total", "Total number of requests received");
    let c = Counter::with_opts(opts).unwrap();
    REGISTRY.register(Box::new(c.clone())).ok();
    c
});

pub static ACTIVE_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| {
    let opts = Opts::new("aiviania_active_connections", "Number of active connections");
    let g = Gauge::with_opts(opts).unwrap();
    REGISTRY.register(Box::new(g.clone())).ok();
    g
});

pub fn gather_metrics() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let mf = REGISTRY.gather();
    encoder.encode(&mf, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
