//! Server module - Main server implementation.
//!
//! This module provides the AivianiaServer that ties together router, middleware, and plugins.

use std::sync::Arc;
use hyper::{Server, service::{make_service_fn, service_fn}, Request, Body};
use crate::router::Router;
use crate::middleware::MiddlewareStack;
use crate::plugin::PluginManager;
use crate::metrics;
use hyper::{Response as HyperResponse, StatusCode};

/// Main server struct.
pub struct AivianiaServer {
    router: Router,
    middleware: MiddlewareStack,
    plugins: PluginManager,
}

impl AivianiaServer {
    /// Create a new server.
    pub fn new(router: Router) -> Self {
        Self {
            router,
            middleware: MiddlewareStack::new(),
            plugins: PluginManager::new(),
        }
    }

    /// Add middleware.
    pub fn with_middleware(mut self, middleware: Box<dyn crate::middleware::Middleware>) -> Self {
        self.middleware.add(middleware);
        self
    }

    /// Add plugin.
    pub fn with_plugin(mut self, plugin: Box<dyn crate::plugin::Plugin>) -> Self {
        self.plugins.add(plugin);
        self
    }

    /// Run the server.
    pub async fn run(self, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let router = Arc::new(self.router);
        let middleware = Arc::new(self.middleware);
        let plugins = Arc::new(self.plugins);

        let make_svc = make_service_fn(move |_| {
            let router = router.clone();
            let middleware = middleware.clone();
            let plugins = plugins.clone();

            async move {
                Ok::<_, hyper::Error>(service_fn(move |mut req: Request<Body>| {
                    let router = router.clone();
                    let middleware = middleware.clone();
                    let plugins = plugins.clone();
                    async move {
                        // Attach plugins manager to request extensions so middlewares/handlers can access plugins
                        req.extensions_mut().insert(plugins.clone());

                        // Increment global request counter for metrics
                        metrics::REQUEST_COUNTER.inc();

                        // Health endpoint
                        if req.uri().path() == "/health" && req.method() == hyper::Method::GET {
                            let resp = HyperResponse::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain")
                                .body(Body::from("ok"))
                                .unwrap();
                            return Ok::<_, hyper::Error>(resp);
                        }

                        // Readiness endpoint: ensure critical plugins like DB are present
                        if req.uri().path() == "/ready" && req.method() == hyper::Method::GET {
                            // Check for database plugin
                            let ready = if let Some(db_plugin) = plugins.get("db") {
                                // presence of plugin is considered OK; more advanced checks may ping DB
                                true
                            } else {
                                false
                            };
                            let status = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
                            let body = if ready { "ready" } else { "not ready" };
                            let resp = HyperResponse::builder()
                                .status(status)
                                .header("content-type", "text/plain")
                                .body(Body::from(body))
                                .unwrap();
                            return Ok::<_, hyper::Error>(resp);
                        }

                        // If the request is for /metrics, return metrics text directly
                        if req.uri().path() == "/metrics" && req.method() == hyper::Method::GET {
                            let body = metrics::gather_metrics();
                            let resp = HyperResponse::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain; version=0.0.4")
                                .body(Body::from(body))
                                .unwrap();
                            return Ok::<_, hyper::Error>(resp);
                        }

                        // Apply before middleware (short-circuit if one returns Err)
                        match middleware.before(req).await {
                            Ok(req) => {
                                // Handle request
                                let resp = router.handle(req, plugins.clone()).await;

                                // Apply after middleware
                                let resp = middleware.after(resp).await;

                                Ok::<_, hyper::Error>(resp)
                            }
                            Err(resp) => Ok::<_, hyper::Error>(resp),
                        }
                    }
                }))
            }
        });

        let addr = addr.parse()?;
        println!("AIVIANIA server running at http://{}", addr);
        Server::bind(&addr).serve(make_svc).await?;
        Ok(())
    }
}

