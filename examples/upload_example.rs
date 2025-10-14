use aiviania::*;
use aiviania::plugin::PluginManager;
use hyper::{Request, Body, StatusCode};
use std::sync::Arc;
use tokio;

/// File upload example demonstrating multipart form data handling
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create upload configuration
    let upload_config = UploadConfig {
        max_file_size: 5 * 1024 * 1024, // 5MB
        max_files: 5,
        allowed_types: vec![
            "image/jpeg".to_string(),
            "image/png".to_string(),
            "image/gif".to_string(),
            "application/pdf".to_string(),
        ],
        upload_dir: std::path::PathBuf::from("./uploads"),
        temp_dir: std::env::temp_dir(),
    };

    // Create upload manager
    let upload_manager = Arc::new(UploadManager::new(upload_config));

    // Create upload middleware
    let upload_middleware = Box::new(UploadMiddleware::new(upload_manager.clone()));

    // Create router
    let mut router = Router::new();

    // File upload endpoint
    let upload_manager_clone = upload_manager.clone();
    router.add_route(Route::new("POST", "/upload", move |req: Request<Body>, _plugins: Arc<PluginManager>| {
        let upload_manager = upload_manager_clone.clone();
        async move {
            // Get uploaded files from request extensions (set by middleware)
            let files = if let Some(files) = req.extensions().get::<Vec<UploadedFile>>() {
                // Store files and clone the file info
                let mut files_to_store = files.clone();
                if let Err(_) = upload_manager.store_files(&mut files_to_store).await {
                    return Response::new(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(r#"{"error": "Failed to store files"}"#));
                }
                files_to_store
            } else {
                Vec::new()
            };

            if files.is_empty() {
                return Response::new(StatusCode::BAD_REQUEST)
                    .body(Body::from(r#"{"error": "No files uploaded"}"#));
            }

            // Process uploaded files
            let file_info: Vec<serde_json::Value> = files
                .iter()
                .map(|file| {
                    serde_json::json!({
                        "filename": file.filename,
                        "content_type": file.content_type,
                        "size": file.size,
                        "field_name": file.field_name,
                        "storage_path": file.storage_path.as_ref().map(|p| p.to_string_lossy().to_string())
                    })
                })
                .collect();

            let response = serde_json::json!({
                "message": "Files uploaded successfully",
                "files": file_info,
                "count": files.len()
            });

            Response::new(StatusCode::OK)
                .body(Body::from(serde_json::to_string(&response).unwrap()))
        }
    }));

    // File list endpoint
    router.add_route(Route::new("GET", "/files", |_req: Request<Body>, _plugins: Arc<PluginManager>| async move {
        // List uploaded files
        let upload_dir = std::path::PathBuf::from("./uploads");

        let mut files = Vec::new();
        if upload_dir.exists() {
            if let Ok(mut entries) = tokio::fs::read_dir(&upload_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(metadata) = entry.metadata().await {
                        if metadata.is_file() {
                            files.push(serde_json::json!({
                                "name": entry.file_name().to_string_lossy(),
                                "size": metadata.len(),
                                "modified": metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                            }));
                        }
                    }
                }
            }
        }

        let response = serde_json::json!({
            "files": files,
            "count": files.len()
        });

        Response::new(StatusCode::OK)
            .body(Body::from(serde_json::to_string(&response).unwrap()))
    }));

    // Create server
    let server = AivianiaServer::new(router)
        .with_middleware(upload_middleware);

    println!("🚀 File Upload Server starting on http://localhost:3000");
    println!("📁 Upload directory: ./uploads");
    println!("📋 Endpoints:");
    println!("  POST /upload - Upload files (multipart/form-data)");
    println!("  GET  /files  - List uploaded files");
    println!();
    println!("📝 Example curl command:");
    println!("curl -X POST -F \"file=@image.jpg\" http://localhost:3000/upload");
    println!();

    // Run server
    server.run("127.0.0.1:3000").await?;

    Ok(())
}