//! AI/ML Configuration

use super::registry::RegistryConfig;
use serde::{Deserialize, Serialize};

/// Main ML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    /// Registry configuration
    pub registry_config: RegistryConfig,

    /// Inference configuration
    pub inference_config: InferenceConfig,

    /// Pipeline configuration
    pub pipeline_config: PipelineConfig,

    /// Metrics configuration
    pub metrics_config: MetricsConfig,

    /// Model configurations
    pub models: Vec<ModelConfig>,

    /// Pipeline configurations
    pub pipelines: Vec<PipelineConfig>,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            registry_config: RegistryConfig::default(),
            inference_config: InferenceConfig::default(),
            pipeline_config: PipelineConfig::default(),
            metrics_config: MetricsConfig::default(),
            models: Vec::new(),
            pipelines: Vec::new(),
        }
    }
}

/// Inference engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,

    /// Request timeout in seconds
    pub request_timeout_secs: u64,

    /// Rate limit per second
    pub rate_limit_per_second: Option<u64>,

    /// Enable auto-scaling
    pub auto_scaling_enabled: bool,

    /// Minimum instances for auto-scaling
    pub min_instances: usize,

    /// Maximum instances for auto-scaling
    pub max_instances: usize,

    /// Scale threshold (0.0-1.0)
    pub scale_threshold: f64,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            request_timeout_secs: 30,
            rate_limit_per_second: None,
            auto_scaling_enabled: false,
            min_instances: 1,
            max_instances: 5,
            scale_threshold: 0.8,
        }
    }
}

/// Pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Default step timeout in milliseconds
    pub default_step_timeout_ms: u64,

    /// Maximum pipeline execution time in seconds
    pub max_execution_time_secs: u64,

    /// Enable pipeline caching
    pub enable_caching: bool,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            default_step_timeout_ms: 30000, // 30 seconds
            max_execution_time_secs: 300,    // 5 minutes
            enable_caching: false,
            cache_ttl_secs: 3600, // 1 hour
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,

    /// Metrics collection interval in seconds
    pub collection_interval_secs: u64,

    /// Enable Prometheus export
    pub prometheus_enabled: bool,

    /// Prometheus port
    pub prometheus_port: u16,

    /// Alert rules
    pub alert_rules: Vec<AlertRuleConfig>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_secs: 60,
            prometheus_enabled: false,
            prometheus_port: 9090,
            alert_rules: Vec::new(),
        }
    }
}

/// Alert rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleConfig {
    pub name: String,
    pub condition: String, // Simple expression like "counter:inference.errors.total > 10"
    pub message: String,
    pub severity: String, // "low", "medium", "high", "critical"
}

/// Model configuration (for loading)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub name: String,
    pub version: String,
    pub model_type: String, // "in_memory", "external", etc.
    pub framework: String,
    pub model_path: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub tags: Vec<String>,
    pub config: Option<serde_json::Value>, // Additional model-specific config
}

/// Pipeline configuration (for loading)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub name: String,
    pub version: String,
    pub steps: Vec<PipelineStepConfig>,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub config: Option<serde_json::Value>, // Additional pipeline-specific config
}

/// Pipeline step configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStepConfig {
    pub name: String,
    pub model_name: String,
    pub model_version: String,
    pub input_mapping: std::collections::HashMap<String, String>,
    pub output_mapping: std::collections::HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub config: Option<serde_json::Value>, // Step-specific config
}

/// Configuration loader
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from file
    pub fn load_from_file(path: &str) -> MlResult<MlConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| MlError::Config(format!("Failed to read config file: {}", e)))?;

        Self::load_from_string(&content)
    }

    /// Load configuration from string
    pub fn load_from_string(content: &str) -> MlResult<MlConfig> {
        serde_yaml::from_str(content)
            .map_err(|e| MlError::Config(format!("Failed to parse config: {}", e)))
    }

    /// Load configuration from environment variables
    pub fn load_from_env() -> MlConfig {
        let mut config = MlConfig::default();

        // Registry config
        if let Ok(storage_type) = std::env::var("ML_REGISTRY_STORAGE_TYPE") {
            config.registry_config.storage_type = storage_type;
        }
        if let Ok(storage_path) = std::env::var("ML_REGISTRY_STORAGE_PATH") {
            config.registry_config.storage_path = Some(storage_path);
        }

        // Inference config
        if let Ok(max_concurrent) = std::env::var("ML_INFERENCE_MAX_CONCURRENT") {
            if let Ok(val) = max_concurrent.parse() {
                config.inference_config.max_concurrent_requests = val;
            }
        }
        if let Ok(timeout) = std::env::var("ML_INFERENCE_TIMEOUT_SECS") {
            if let Ok(val) = timeout.parse() {
                config.inference_config.request_timeout_secs = val;
            }
        }

        // Metrics config
        if let Ok(enabled) = std::env::var("ML_METRICS_ENABLED") {
            config.metrics_config.enabled = enabled.to_lowercase() == "true";
        }
        if let Ok(prometheus_enabled) = std::env::var("ML_PROMETHEUS_ENABLED") {
            config.metrics_config.prometheus_enabled = prometheus_enabled.to_lowercase() == "true";
        }

        config
    }

    /// Merge configurations (file config takes precedence over env)
    pub fn merge_configs(file_config: MlConfig, env_config: MlConfig) -> MlConfig {
        // For now, just return file config. In a real implementation,
        // you'd merge them properly with env vars overriding defaults
        file_config
    }
}

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate ML configuration
    pub fn validate_config(config: &MlConfig) -> MlResult<()> {
        // Validate inference config
        if config.inference_config.max_concurrent_requests == 0 {
            return Err(MlError::Config("max_concurrent_requests must be > 0".to_string()));
        }

        if config.inference_config.request_timeout_secs == 0 {
            return Err(MlError::Config("request_timeout_secs must be > 0".to_string()));
        }

        if config.inference_config.scale_threshold < 0.0 || config.inference_config.scale_threshold > 1.0 {
            return Err(MlError::Config("scale_threshold must be between 0.0 and 1.0".to_string()));
        }

        // Validate pipeline config
        if config.pipeline_config.max_execution_time_secs == 0 {
            return Err(MlError::Config("max_execution_time_secs must be > 0".to_string()));
        }

        // Validate models
        for model in &config.models {
            if model.name.is_empty() {
                return Err(MlError::Config("Model name cannot be empty".to_string()));
            }
            if model.version.is_empty() {
                return Err(MlError::Config("Model version cannot be empty".to_string()));
            }
        }

        // Validate pipelines
        for pipeline in &config.pipelines {
            if pipeline.name.is_empty() {
                return Err(MlError::Config("Pipeline name cannot be empty".to_string()));
            }
            if pipeline.steps.is_empty() {
                return Err(MlError::Config("Pipeline must have at least one step".to_string()));
            }
        }

        Ok(())
    }
}