//! Server module - Main server implementation.
//!
//! This module provides the AivianiaServer that ties together router, middleware, and plugins.

use std::sync::Arc;
use hyper::{Server, service::{make_service_fn, service_fn}, Request, Body};
use crate::router::Router;
use crate::middleware::MiddlewareStack;
use crate::plugin::PluginManager;

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
                Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                    let router = router.clone();
                    let middleware = middleware.clone();
                    let plugins = plugins.clone();
                    async move {
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
