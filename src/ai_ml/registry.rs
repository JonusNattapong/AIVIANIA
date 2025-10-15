//! Model registry and versioning

use super::{types::*, MlError, MlResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Model registry for managing ML models
pub struct ModelRegistry {
    models: Arc<RwLock<HashMap<String, HashMap<String, ModelEntry>>>>,
    storage: Box<dyn ModelStorage>,
}

impl ModelRegistry {
    /// Create a new model registry
    pub fn new(config: RegistryConfig) -> Self {
        let storage: Box<dyn ModelStorage> = match config.storage_type.as_str() {
            "memory" => Box::new(MemoryStorage::new()),
            "file" => Box::new(FileStorage::new(
                config
                    .storage_path
                    .unwrap_or_else(|| "./models".to_string()),
            )),
            _ => Box::new(MemoryStorage::new()),
        };

        Self {
            models: Arc::new(RwLock::new(HashMap::new())),
            storage,
        }
    }

    /// Register a model
    pub async fn register_model(
        &self,
        metadata: ModelMetadata,
        model_data: Vec<u8>,
    ) -> MlResult<()> {
        let entry = ModelEntry {
            metadata: metadata.clone(),
            data: model_data,
            registered_at: chrono::Utc::now(),
            status: ModelStatus::Active,
        };

        // Store in backend
        self.storage
            .store(&metadata.name, &metadata.version, &entry)
            .await?;

        // Update in-memory index
        let mut models = self.models.write().await;
        let model_versions = models
            .entry(metadata.name.clone())
            .or_insert_with(HashMap::new);
        model_versions.insert(metadata.version.clone(), entry);

        Ok(())
    }

    /// Get a model by name and version
    pub async fn get_model(&self, name: &str, version: &str) -> MlResult<ModelEntry> {
        // Check in-memory cache first
        {
            let models = self.models.read().await;
            if let Some(model_versions) = models.get(name) {
                if let Some(entry) = model_versions.get(version) {
                    return Ok(entry.clone());
                }
            }
        }

        // Load from storage
        let entry = self.storage.load(name, version).await?;

        // Update cache
        let mut models = self.models.write().await;
        let model_versions = models.entry(name.to_string()).or_insert_with(HashMap::new);
        model_versions.insert(version.to_string(), entry.clone());

        Ok(entry)
    }

    /// List model versions
    pub async fn list_versions(&self, name: &str) -> MlResult<Vec<String>> {
        let models = self.models.read().await;
        if let Some(model_versions) = models.get(name) {
            let versions: Vec<String> = model_versions.keys().cloned().collect();
            Ok(versions)
        } else {
            // Load from storage if not in cache
            let versions = self.storage.list_versions(name).await?;
            Ok(versions)
        }
    }

    /// List all models
    pub async fn list_models(&self) -> MlResult<Vec<String>> {
        let models = self.models.read().await;
        let model_names: Vec<String> = models.keys().cloned().collect();
        Ok(model_names)
    }

    /// Delete a model version
    pub async fn delete_model(&self, name: &str, version: &str) -> MlResult<bool> {
        // Remove from storage
        let deleted = self.storage.delete(name, version).await?;

        if deleted {
            // Remove from cache
            let mut models = self.models.write().await;
            if let Some(model_versions) = models.get_mut(name) {
                model_versions.remove(version);
                // Remove model entry if no versions left
                if model_versions.is_empty() {
                    models.remove(name);
                }
            }
        }

        Ok(deleted)
    }

    /// Update model status
    pub async fn update_status(
        &self,
        name: &str,
        version: &str,
        status: ModelStatus,
    ) -> MlResult<()> {
        let mut models = self.models.write().await;
        if let Some(model_versions) = models.get_mut(name) {
            if let Some(entry) = model_versions.get_mut(version) {
                entry.status = status;
                // Update storage
                self.storage.store(name, version, entry).await?;
            } else {
                return Err(MlError::NotFound(format!(
                    "Model '{}' version '{}' not found",
                    name, version
                )));
            }
        } else {
            return Err(MlError::NotFound(format!("Model '{}' not found", name)));
        }

        Ok(())
    }

    /// Get model metadata
    pub async fn get_metadata(&self, name: &str, version: &str) -> MlResult<ModelMetadata> {
        let entry = self.get_model(name, version).await?;
        Ok(entry.metadata)
    }

    /// Search models by tags
    pub async fn search_by_tags(&self, tags: &[String]) -> MlResult<Vec<ModelMetadata>> {
        let models = self.models.read().await;
        let mut results = Vec::new();

        for model_versions in models.values() {
            for entry in model_versions.values() {
                if entry.status == ModelStatus::Active {
                    let has_all_tags = tags.iter().all(|tag| entry.metadata.tags.contains(tag));
                    if has_all_tags {
                        results.push(entry.metadata.clone());
                    }
                }
            }
        }

        Ok(results)
    }

    /// Health check
    pub async fn health_check(&self) -> serde_json::Value {
        let models = self.models.read().await;
        let total_models = models.len();
        let total_versions: usize = models.values().map(|v| v.len()).sum();

        serde_json::json!({
            "status": "healthy",
            "total_models": total_models,
            "total_versions": total_versions,
            "storage_type": "available"
        })
    }
}

/// Model entry in registry
#[derive(Debug, Clone)]
pub struct ModelEntry {
    pub metadata: ModelMetadata,
    pub data: Vec<u8>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub status: ModelStatus,
}

/// Model status
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModelStatus {
    Active,
    Inactive,
    Deprecated,
    Archived,
}

/// Model storage trait
#[async_trait]
pub trait ModelStorage: Send + Sync {
    /// Store a model
    async fn store(&self, name: &str, version: &str, entry: &ModelEntry) -> MlResult<()>;

    /// Load a model
    async fn load(&self, name: &str, version: &str) -> MlResult<ModelEntry>;

    /// Delete a model
    async fn delete(&self, name: &str, version: &str) -> MlResult<bool>;

    /// List versions of a model
    async fn list_versions(&self, name: &str) -> MlResult<Vec<String>>;
}

/// In-memory storage implementation
pub struct MemoryStorage {
    data: Arc<RwLock<HashMap<String, HashMap<String, ModelEntry>>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ModelStorage for MemoryStorage {
    async fn store(&self, name: &str, version: &str, entry: &ModelEntry) -> MlResult<()> {
        let mut data = self.data.write().await;
        let model_versions = data.entry(name.to_string()).or_insert_with(HashMap::new);
        model_versions.insert(version.to_string(), entry.clone());
        Ok(())
    }

    async fn load(&self, name: &str, version: &str) -> MlResult<ModelEntry> {
        let data = self.data.read().await;
        data.get(name)
            .and_then(|versions| versions.get(version))
            .cloned()
            .ok_or_else(|| {
                MlError::NotFound(format!("Model '{}' version '{}' not found", name, version))
            })
    }

    async fn delete(&self, name: &str, version: &str) -> MlResult<bool> {
        let mut data = self.data.write().await;
        if let Some(model_versions) = data.get_mut(name) {
            let existed = model_versions.remove(version).is_some();
            if model_versions.is_empty() {
                data.remove(name);
            }
            Ok(existed)
        } else {
            Ok(false)
        }
    }

    async fn list_versions(&self, name: &str) -> MlResult<Vec<String>> {
        let data = self.data.read().await;
        if let Some(model_versions) = data.get(name) {
            let versions: Vec<String> = model_versions.keys().cloned().collect();
            Ok(versions)
        } else {
            Ok(Vec::new())
        }
    }
}

/// File system storage implementation
pub struct FileStorage {
    base_path: String,
}

impl FileStorage {
    pub fn new(base_path: String) -> Self {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&base_path).unwrap_or_default();
        Self { base_path }
    }

    fn get_model_path(&self, name: &str, version: &str) -> String {
        format!("{}/{}/{}/model.bin", self.base_path, name, version)
    }

    fn get_metadata_path(&self, name: &str, version: &str) -> String {
        format!("{}/{}/{}/metadata.json", self.base_path, name, version)
    }
}

#[async_trait]
impl ModelStorage for FileStorage {
    async fn store(&self, name: &str, version: &str, entry: &ModelEntry) -> MlResult<()> {
        let model_dir = format!("{}/{}/{}", self.base_path, name, version);
        tokio::fs::create_dir_all(&model_dir)
            .await
            .map_err(|e| MlError::Registry(format!("Failed to create directory: {}", e)))?;

        // Save model data
        let model_path = self.get_model_path(name, version);
        tokio::fs::write(&model_path, &entry.data)
            .await
            .map_err(|e| MlError::Registry(format!("Failed to write model data: {}", e)))?;

        // Save metadata
        let metadata_path = self.get_metadata_path(name, version);
        let metadata_json = serde_json::to_string_pretty(&entry)
            .map_err(|e| MlError::Serialization(e.to_string()))?;
        tokio::fs::write(&metadata_path, metadata_json)
            .await
            .map_err(|e| MlError::Registry(format!("Failed to write metadata: {}", e)))?;

        Ok(())
    }

    async fn load(&self, name: &str, version: &str) -> MlResult<ModelEntry> {
        let metadata_path = self.get_metadata_path(name, version);

        // Load metadata first
        let metadata_content = tokio::fs::read_to_string(&metadata_path)
            .await
            .map_err(|_| {
                MlError::NotFound(format!("Model '{}' version '{}' not found", name, version))
            })?;

        let entry: ModelEntry = serde_json::from_str(&metadata_content)
            .map_err(|e| MlError::Deserialization(e.to_string()))?;

        Ok(entry)
    }

    async fn delete(&self, name: &str, version: &str) -> MlResult<bool> {
        let model_dir = format!("{}/{}/{}", self.base_path, name, version);

        if tokio::fs::metadata(&model_dir).await.is_ok() {
            tokio::fs::remove_dir_all(&model_dir)
                .await
                .map_err(|e| MlError::Registry(format!("Failed to delete model: {}", e)))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list_versions(&self, name: &str) -> MlResult<Vec<String>> {
        let model_dir = format!("{}/{}", self.base_path, name);

        if let Ok(mut entries) = tokio::fs::read_dir(&model_dir).await {
            let mut versions = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(file_type) = entry.file_type().await {
                    if file_type.is_dir() {
                        if let Some(version) = entry.file_name().to_str() {
                            versions.push(version.to_string());
                        }
                    }
                }
            }
            Ok(versions)
        } else {
            Ok(Vec::new())
        }
    }
}

/// Registry configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RegistryConfig {
    pub storage_type: String,
    pub storage_path: Option<String>,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            storage_type: "memory".to_string(),
            storage_path: None,
        }
    }
}
