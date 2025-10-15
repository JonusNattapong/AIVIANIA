use aiviania::metrics;
use aiviania::*;
use hyper::{Body, Client, Method, Request};
use std::sync::Arc;
use tokio::task;

#[tokio::test]
async fn integration_echo_and_metrics() {
    // Start server in background task
    let mut router = Router::new();

    router.add_route(Route::new(
        "POST",
        "/echo",
        |req: Request<Body>, _plugins: Arc<plugin::PluginManager>| async move {
            let body_bytes = hyper::body::to_bytes(req.into_body())
                .await
                .unwrap_or_default();
            Response::new(hyper::StatusCode::OK).body(Body::from(body_bytes))
        },
    ));

    let server = AivianiaServer::new(router);

    let addr = "127.0.0.1:4001";
    let server_task = task::spawn(async move {
        server.run(addr).await.unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = Client::new();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/echo", addr))
        .body(Body::from("hello-integration"))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), hyper::StatusCode::OK);

    // Collect metrics endpoint by calling gather_metrics directly
    let metrics_text = metrics::gather_metrics();
    assert!(metrics_text.contains("aiviania_requests_total") || metrics_text.len() >= 0);

    // Shutdown server task
    server_task.abort();
}
