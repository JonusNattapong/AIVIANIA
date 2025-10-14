//! ML Pipeline orchestration

use super::{MlError, MlResult, types::*};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Pipeline step result
#[derive(Debug, Clone)]
pub struct StepResult {
    pub step_name: String,
    pub output: InferenceOutput,
    pub success: bool,
    pub error: Option<String>,
}

/// Pipeline execution result
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub pipeline_name: String,
    pub pipeline_version: String,
    pub steps: Vec<StepResult>,
    pub final_output: Option<InferenceOutput>,
    pub total_processing_time_ms: u64,
    pub success: bool,
}

/// ML Pipeline orchestrator
pub struct PipelineOrchestrator {
    pipelines: Arc<RwLock<HashMap<String, PipelineConfig>>>,
    models: Arc<RwLock<HashMap<String, Box<dyn MlModel>>>>,
}

impl PipelineOrchestrator {
    /// Create a new pipeline orchestrator
    pub fn new() -> Self {
        Self {
            pipelines: Arc::new(RwLock::new(HashMap::new())),
            models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a pipeline
    pub async fn register_pipeline(&self, config: PipelineConfig) -> MlResult<()> {
        let mut pipelines = self.pipelines.write().await;
        pipelines.insert(config.name.clone(), config);
        Ok(())
    }

    /// Unregister a pipeline
    pub async fn unregister_pipeline(&self, name: &str) -> MlResult<bool> {
        let mut pipelines = self.pipelines.write().await;
        Ok(pipelines.remove(name).is_some())
    }

    /// Register a model for pipeline use
    pub async fn register_model(&self, name: String, model: Box<dyn MlModel>) -> MlResult<()> {
        let mut models = self.models.write().await;
        models.insert(name, model);
        Ok(())
    }

    /// Execute a pipeline
    pub async fn execute_pipeline(
        &self,
        pipeline_name: &str,
        input: InferenceInput,
    ) -> MlResult<PipelineResult> {
        let pipelines = self.pipelines.read().await;
        let config = pipelines.get(pipeline_name)
            .ok_or_else(|| MlError::NotFound(format!("Pipeline '{}' not found", pipeline_name)))?;

        let start_time = std::time::Instant::now();
        let mut step_results = Vec::new();
        let mut current_data = input.data;
        let mut current_metadata = input.metadata.unwrap_or_default();

        for step in &config.steps {
            let step_start = std::time::Instant::now();

            // Get model for this step
            let models = self.models.read().await;
            let model = models.get(&format!("{}:{}", step.model_name, step.model_version))
                .ok_or_else(|| MlError::NotFound(format!("Model '{}' version '{}' not found",
                    step.model_name, step.model_version)))?;

            // Prepare input for this step
            let step_input = self.prepare_step_input(&step.input_mapping, &current_data, &current_metadata)?;

            let inference_input = InferenceInput {
                data: step_input,
                metadata: Some(current_metadata.clone()),
            };

            // Execute step with timeout
            let timeout_duration = step.timeout_ms
                .map(|ms| std::time::Duration::from_millis(ms))
                .unwrap_or(std::time::Duration::from_secs(30));

            let step_result = match timeout(timeout_duration, model.predict(inference_input)).await {
                Ok(Ok(output)) => {
                    // Update current data and metadata for next step
                    current_data = output.result.clone();
                    if let Some(ref meta) = output.metadata {
                        current_metadata.extend(meta.clone());
                    }

                    StepResult {
                        step_name: step.name.clone(),
                        output,
                        success: true,
                        error: None,
                    }
                }
                Ok(Err(e)) => StepResult {
                    step_name: step.name.clone(),
                    output: InferenceOutput {
                        result: serde_json::json!({"error": "step_failed"}),
                        confidence: None,
                        metadata: None,
                        processing_time_ms: step_start.elapsed().as_millis() as u64,
                    },
                    success: false,
                    error: Some(e.to_string()),
                },
                Err(_) => StepResult {
                    step_name: step.name.clone(),
                    output: InferenceOutput {
                        result: serde_json::json!({"error": "timeout"}),
                        confidence: None,
                        metadata: None,
                        processing_time_ms: step_start.elapsed().as_millis() as u64,
                    },
                    success: false,
                    error: Some("Step timeout".to_string()),
                },
            };

            step_results.push(step_result.clone());

            // Stop pipeline if step failed
            if !step_result.success {
                break;
            }
        }

        let total_time = start_time.elapsed().as_millis() as u64;
        let success = step_results.iter().all(|r| r.success);

        let final_output = if success && !step_results.is_empty() {
            Some(step_results.last().unwrap().output.clone())
        } else {
            None
        };

        Ok(PipelineResult {
            pipeline_name: config.name.clone(),
            pipeline_version: config.version.clone(),
            steps: step_results,
            final_output,
            total_processing_time_ms: total_time,
            success,
        })
    }

    /// Prepare input data for a pipeline step
    fn prepare_step_input(
        &self,
        input_mapping: &HashMap<String, String>,
        current_data: &serde_json::Value,
        current_metadata: &HashMap<String, String>,
    ) -> MlResult<serde_json::Value> {
        let mut step_input = serde_json::Map::new();

        for (target_field, source_expr) in input_mapping {
            let value = self.resolve_expression(source_expr, current_data, current_metadata)?;
            step_input.insert(target_field.clone(), value);
        }

        Ok(serde_json::Value::Object(step_input))
    }

    /// Resolve expression for input mapping
    fn resolve_expression(
        &self,
        expr: &str,
        data: &serde_json::Value,
        metadata: &HashMap<String, String>,
    ) -> MlResult<serde_json::Value> {
        // Simple expression resolver - supports data.field and metadata.key
        if expr.starts_with("data.") {
            let field = &expr[5..];
            if let Some(value) = data.get(field) {
                Ok(value.clone())
            } else {
                Err(MlError::Pipeline(format!("Field '{}' not found in data", field)))
            }
        } else if expr.starts_with("metadata.") {
            let key = &expr[9..];
            if let Some(value) = metadata.get(key) {
                Ok(serde_json::Value::String(value.clone()))
            } else {
                Err(MlError::Pipeline(format!("Key '{}' not found in metadata", key)))
            }
        } else {
            // Direct value
            Ok(serde_json::Value::String(expr.to_string()))
        }
    }

    /// Get pipeline configuration
    pub async fn get_pipeline(&self, name: &str) -> MlResult<PipelineConfig> {
        let pipelines = self.pipelines.read().await;
        pipelines.get(name)
            .cloned()
            .ok_or_else(|| MlError::NotFound(format!("Pipeline '{}' not found", name)))
    }

    /// List all pipelines
    pub async fn list_pipelines(&self) -> Vec<String> {
        let pipelines = self.pipelines.read().await;
        pipelines.keys().cloned().collect()
    }

    /// Validate pipeline configuration
    pub async fn validate_pipeline(&self, config: &PipelineConfig) -> MlResult<()> {
        if config.steps.is_empty() {
            return Err(MlError::Validation("Pipeline must have at least one step".to_string()));
        }

        let models = self.models.read().await;
        for step in &config.steps {
            let model_key = format!("{}:{}", step.model_name, step.model_version);
            if !models.contains_key(&model_key) {
                return Err(MlError::Validation(format!("Model '{}' version '{}' not registered", step.model_name, step.model_version)));
            }
        }

        Ok(())
    }
}

/// Pipeline builder for fluent API
pub struct PipelineBuilder {
    config: PipelineConfig,
}

impl PipelineBuilder {
    /// Create a new pipeline builder
    pub fn new(name: String, version: String) -> Self {
        Self {
            config: PipelineConfig {
                name,
                version,
                steps: Vec::new(),
                input_schema: serde_json::json!({}),
                output_schema: serde_json::json!({}),
            },
        }
    }

    /// Add a pipeline step
    pub fn add_step(mut self, step: PipelineStep) -> Self {
        self.config.steps.push(step);
        self
    }

    /// Set input schema
    pub fn input_schema(mut self, schema: serde_json::Value) -> Self {
        self.config.input_schema = schema;
        self
    }

    /// Set output schema
    pub fn output_schema(mut self, schema: serde_json::Value) -> Self {
        self.config.output_schema = schema;
        self
    }

    /// Build the pipeline configuration
    pub fn build(self) -> PipelineConfig {
        self.config
    }
}

/// Pipeline execution context for advanced use cases
pub struct PipelineContext {
    pub pipeline_name: String,
    pub execution_id: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub variables: HashMap<String, serde_json::Value>,
    pub logs: Vec<String>,
}

impl PipelineContext {
    /// Create a new pipeline context
    pub fn new(pipeline_name: String) -> Self {
        Self {
            pipeline_name,
            execution_id: uuid::Uuid::new_v4().to_string(),
            start_time: chrono::Utc::now(),
            variables: HashMap::new(),
            logs: Vec::new(),
        }
    }

    /// Add a log entry
    pub fn log(&mut self, message: String) {
        self.logs.push(format!("[{}] {}", chrono::Utc::now().to_rfc3339(), message));
    }

    /// Set a variable
    pub fn set_variable(&mut self, key: String, value: serde_json::Value) {
        self.variables.insert(key, value);
    }

    /// Get a variable
    pub fn get_variable(&self, key: &str) -> Option<&serde_json::Value> {
        self.variables.get(key)
    }
}