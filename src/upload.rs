use multer::Multipart;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Configuration for file upload handling
#[derive(Debug, Clone)]
pub struct UploadConfig {
    /// Maximum file size in bytes (default: 10MB)
    pub max_file_size: usize,
    /// Maximum number of files per request (default: 10)
    pub max_files: usize,
    /// Allowed MIME types (empty means all types allowed)
    pub allowed_types: Vec<String>,
    /// Upload directory path
    pub upload_dir: PathBuf,
    /// Temporary directory for processing
    pub temp_dir: PathBuf,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 10,
            allowed_types: vec![],
            upload_dir: PathBuf::from("./uploads"),
            temp_dir: std::env::temp_dir(),
        }
    }
}

/// Represents an uploaded file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UploadedFile {
    /// Original filename
    pub filename: String,
    /// MIME type
    pub content_type: String,
    /// File size in bytes
    pub size: usize,
    /// Temporary file path (if stored temporarily)
    pub temp_path: Option<PathBuf>,
    /// Final storage path (if moved to permanent storage)
    pub storage_path: Option<PathBuf>,
    /// Field name from the form
    pub field_name: String,
}

/// Upload manager for handling file uploads
pub struct UploadManager {
    config: UploadConfig,
}

impl UploadManager {
    /// Create a new upload manager with the given configuration
    pub fn new(config: UploadConfig) -> Self {
        Self { config }
    }

    /// Process multipart form data from a request
    pub async fn process_multipart(
        &self,
        boundary: &str,
        body: hyper::Body,
    ) -> Result<Vec<UploadedFile>, UploadError> {
        // Create multipart parser
        let mut multipart = Multipart::new(body, boundary);

        let mut files = Vec::new();
        let mut file_count = 0;

        // Process each field
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(UploadError::Multipart)?
        {
            file_count += 1;

            // Check file limit
            if file_count > self.config.max_files {
                return Err(UploadError::TooManyFiles(self.config.max_files));
            }

            let field_name = field.name().unwrap_or("unknown").to_string();

            // Check if this field has a filename (it's a file field)
            if let Some(filename) = field.file_name() {
                let filename = filename.to_string(); // Clone the filename
                let content_type = field
                    .content_type()
                    .map(|ct| ct.to_string())
                    .unwrap_or_else(|| "application/octet-stream".to_string());

                // Validate file type if restrictions are set
                if !self.config.allowed_types.is_empty()
                    && !self.config.allowed_types.contains(&content_type)
                {
                    return Err(UploadError::InvalidFileType(content_type));
                }

                // Create temporary file
                let temp_file =
                    NamedTempFile::new_in(&self.config.temp_dir).map_err(UploadError::Io)?;

                let temp_path = temp_file.path().to_path_buf();
                let mut temp_file = tokio::fs::File::create(&temp_path)
                    .await
                    .map_err(UploadError::Io)?;

                let mut size = 0usize;

                // Read and write file data in chunks
                while let Some(chunk) = field.chunk().await.map_err(UploadError::Multipart)? {
                    // Check file size limit
                    size += chunk.len();
                    if size > self.config.max_file_size {
                        // Clean up temp file
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        return Err(UploadError::FileTooLarge(self.config.max_file_size));
                    }

                    temp_file.write_all(&chunk).await.map_err(UploadError::Io)?;
                }

                temp_file.flush().await.map_err(UploadError::Io)?;

                let uploaded_file = UploadedFile {
                    filename,
                    content_type,
                    size,
                    temp_path: Some(temp_path),
                    storage_path: None,
                    field_name,
                };

                files.push(uploaded_file);
            }
        }

        Ok(files)
    }

    /// Compatibility adapter used by examples: handle_upload takes a mutable Request and
    /// processes multipart data, returning a Vec<UploadedFile> on success.
    pub async fn handle_upload(
        &self,
        req: &mut hyper::Request<hyper::Body>,
    ) -> Result<Vec<UploadedFile>, UploadError> {
        // Extract boundary from content-type
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "".to_string());
        let boundary = content_type
            .split("boundary=")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();

        if boundary.is_empty() {
            return Err(UploadError::Config("Missing multipart boundary".to_string()));
        }

    // Move the body out of the request by replacing it with an empty Body
    let body = std::mem::take(req.body_mut());
    self.process_multipart(&boundary, body).await
    }

    /// Move uploaded files to permanent storage
    pub async fn store_files(&self, files: &mut [UploadedFile]) -> Result<(), UploadError> {
        // Ensure upload directory exists
        fs::create_dir_all(&self.config.upload_dir)
            .await
            .map_err(UploadError::Io)?;

        for file in files.iter_mut() {
            if let Some(temp_path) = &file.temp_path {
                // Generate unique filename
                let file_path = PathBuf::from(&file.filename);
                let extension = file_path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("");

                let unique_filename = format!("{}.{}", Uuid::new_v4(), extension);
                let storage_path = self.config.upload_dir.join(unique_filename);

                // Move file to permanent storage
                fs::rename(temp_path, &storage_path)
                    .await
                    .map_err(UploadError::Io)?;

                file.storage_path = Some(storage_path);
                file.temp_path = None;
            }
        }

        Ok(())
    }

    /// Clean up temporary files
    pub async fn cleanup_temp_files(&self, files: &[UploadedFile]) -> Result<(), UploadError> {
        for file in files {
            if let Some(temp_path) = &file.temp_path {
                let _ = fs::remove_file(temp_path).await; // Ignore errors during cleanup
            }
        }
        Ok(())
    }

    /// Validate file type based on MIME type and file extension
    pub fn validate_file_type(&self, filename: &str, content_type: &str) -> bool {
        if self.config.allowed_types.is_empty() {
            return true;
        }

        // Check MIME type
        if self
            .config
            .allowed_types
            .contains(&content_type.to_string())
        {
            return true;
        }

        // Check file extension
        if let Some(extension) = PathBuf::from(filename).extension() {
            if let Some(ext_str) = extension.to_str() {
                let guessed_mime = mime_guess::from_ext(ext_str).first_or_octet_stream();
                if self
                    .config
                    .allowed_types
                    .contains(&guessed_mime.to_string())
                {
                    return true;
                }
            }
        }

        false
    }
}

// Re-export alias for backwards compatibility
pub use UploadManager as UploadService;

/// Errors that can occur during file upload
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Multipart parsing error: {0}")]
    Multipart(multer::Error),
    #[error("File too large (max: {0} bytes)")]
    FileTooLarge(usize),
    #[error("Too many files (max: {0})")]
    TooManyFiles(usize),
    #[error("Invalid file type: {0}")]
    InvalidFileType(String),
    #[error("Upload configuration error: {0}")]
    Config(String),
}

/// Middleware for handling file uploads
pub struct UploadMiddleware {
    upload_manager: Arc<UploadManager>,
}

impl UploadMiddleware {
    pub fn new(upload_manager: Arc<UploadManager>) -> Self {
        Self { upload_manager }
    }
}

impl crate::middleware::Middleware for UploadMiddleware {
    fn before(
        &self,
        req: hyper::Request<hyper::Body>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<hyper::Request<hyper::Body>, hyper::Response<hyper::Body>>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // Check if this is a multipart request
            if let Some(content_type) = req.headers().get(hyper::header::CONTENT_TYPE) {
                if let Ok(ct_str) = content_type.to_str() {
                    if ct_str.starts_with("multipart/form-data") {
                        // Extract boundary
                        if let Some(boundary) = ct_str.split("boundary=").nth(1) {
                            let boundary = boundary.to_string();

                            // Process multipart data
                            match self
                                .upload_manager
                                .process_multipart(&boundary, req.into_body())
                                .await
                            {
                                Ok(files) => {
                                    // Create new request with uploaded files in extensions
                                    let (parts, _) =
                                        hyper::Request::new(hyper::Body::empty()).into_parts();

                                    let mut req =
                                        hyper::Request::from_parts(parts, hyper::Body::empty());

                                    // Store uploaded files in extensions
                                    req.extensions_mut().insert(files);

                                    return Ok(req);
                                }
                                Err(e) => {
                                    // Return error response
                                    let error_body = format!("Upload error: {}", e);
                                    let response = hyper::Response::builder()
                                        .status(400)
                                        .body(hyper::Body::from(error_body))
                                        .unwrap();
                                    return Err(response);
                                }
                            }
                        }
                    }
                }
            }

            // Not a multipart request, pass through
            Ok(req)
        })
    }
}

/// Helper function to get uploaded files from request extensions
pub fn get_uploaded_files(req: &hyper::Request<hyper::Body>) -> Option<&Vec<UploadedFile>> {
    req.extensions().get::<Vec<UploadedFile>>()
}

/// Helper function to extract uploaded files and move them to storage
pub async fn extract_and_store_files(
    req: &mut hyper::Request<hyper::Body>,
    upload_manager: &UploadManager,
) -> Result<Vec<UploadedFile>, UploadError> {
    if let Some(files) = req.extensions_mut().remove::<Vec<UploadedFile>>() {
        let mut files = files;
        upload_manager.store_files(&mut files).await?;
        Ok(files)
    } else {
        Ok(vec![])
    }
}
