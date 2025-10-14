//! AI/ML Integration Module
//!
//! Provides comprehensive AI/ML capabilities including:
//!
//! - Model serving and inference endpoints
//! - ML pipeline orchestration
//! - Model registry and versioning
//! - Batch processing and streaming inference
//! - Model monitoring and metrics
//! - Integration with popular ML frameworks

pub mod model;
pub mod pipeline;
pub mod registry;
pub mod inference;
pub mod metrics;
pub mod config;

pub use model::*;
pub use pipeline::*;
pub use registry::*;
pub use inference::*;
pub use metrics::*;
pub use config::*;

/// Result type for AI/ML operations
pub type MlResult<T> = Result<T, MlError>;

/// AI/ML operation errors
#[derive(Debug, thiserror::Error)]
pub enum MlError {
    #[error("Model loading error: {0}")]
    ModelLoad(String),

    #[error("Inference error: {0}")]
    Inference(String),

    #[error("Pipeline error: {0}")]
    Pipeline(String),

    #[error("Registry error: {0}")]
    Registry(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Timeout error")]
    Timeout,

    #[error("Rate limit exceeded")]
    RateLimit,
}

/// Data types for ML operations
pub mod types {
    use serde::{Deserialize, Serialize};

    /// Input data for inference
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InferenceInput {
        pub data: serde_json::Value,
        pub metadata: Option<std::collections::HashMap<String, String>>,
    }

    /// Output data from inference
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InferenceOutput {
        pub result: serde_json::Value,
        pub confidence: Option<f64>,
        pub metadata: Option<std::collections::HashMap<String, String>>,
        pub processing_time_ms: u64,
    }

    /// Model metadata
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ModelMetadata {
        pub name: String,
        pub version: String,
        pub framework: String,
        pub input_schema: serde_json::Value,
        pub output_schema: serde_json::Value,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub tags: Vec<String>,
    }

    /// Pipeline step configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PipelineStep {
        pub name: String,
        pub model_name: String,
        pub model_version: String,
        pub input_mapping: std::collections::HashMap<String, String>,
        pub output_mapping: std::collections::HashMap<String, String>,
        pub timeout_ms: Option<u64>,
    }

    /// Pipeline configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PipelineConfig {
        pub name: String,
        pub version: String,
        pub steps: Vec<PipelineStep>,
        pub input_schema: serde_json::Value,
        pub output_schema: serde_json::Value,
    }
}

/// ML service for managing AI/ML operations
pub struct MlService {
    registry: ModelRegistry,
    pipeline_orchestrator: PipelineOrchestrator,
    metrics_collector: MetricsCollector,
}

impl MlService {
    /// Create a new ML service
    pub fn new(config: MlConfig) -> Self {
        Self {
            registry: ModelRegistry::new(config.registry_config),
            pipeline_orchestrator: PipelineOrchestrator::new(),
            metrics_collector: MetricsCollector::new(),
        }
    }

    /// Get model registry
    pub fn registry(&self) -> &ModelRegistry {
        &self.registry
    }

    /// Get pipeline orchestrator
    pub fn pipeline_orchestrator(&self) -> &PipelineOrchestrator {
        &self.pipeline_orchestrator
    }

    /// Get metrics collector
    pub fn metrics_collector(&self) -> &MetricsCollector {
        &self.metrics_collector
    }

    /// Health check for ML service
    pub async fn health_check(&self) -> MlResult<serde_json::Value> {
        let registry_health = self.registry.health_check().await;
        let metrics = self.metrics_collector.get_summary().await;

        Ok(serde_json::json!({
            "status": "healthy",
            "registry": registry_health,
            "metrics": metrics,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}