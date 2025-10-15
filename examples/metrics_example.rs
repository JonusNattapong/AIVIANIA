use aiviania::observability;
use hyper::{Request, Body, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use std::sync::Arc;

async fn metrics_handler(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let body = observability::gather_metrics();
    Ok(Response::new(Body::from(body)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    observability::init_tracing();

    let make_svc = make_service_fn(|_conn| async move {
        Ok::<_, hyper::Error>(service_fn(|req| async move {
            if req.uri().path() == "/metrics" {
                metrics_handler(req).await
            } else {
                Ok(Response::new(Body::from("Hello from AIVIANIA example")))
            }
        }))
    });

    let addr = ([127,0,0,1], 4000).into();
    let server = Server::bind(&addr).serve(make_svc);
    println!("Listening on http://{}", addr);
    server.await?;
    Ok(())
}
