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

pub static DB_UP: Lazy<Gauge> = Lazy::new(|| {
    let opts = Opts::new("aiviania_db_up", "Whether the database is reachable (1 = up, 0 = down)");
    let g = Gauge::with_opts(opts).unwrap();
    REGISTRY.register(Box::new(g.clone())).ok();
    g
});

pub static DB_SCHEMA_OK: Lazy<Gauge> = Lazy::new(|| {
    let opts = Opts::new("aiviania_db_schema_ok", "Whether required DB schema/tables exist (1 = ok, 0 = missing)");
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
