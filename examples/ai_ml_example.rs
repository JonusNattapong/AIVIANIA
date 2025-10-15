//! AI/ML Integration Example
//!
//! This example demonstrates:
//! - Setting up ML models and registry
//! - Creating inference pipelines
//! - Running batch and streaming inference
//! - Monitoring ML performance
//! - Using ML middleware with HTTP endpoints

#[cfg(feature = "ai_ml")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aiviania::ai_ml::{
        config::{ConfigLoader, MlConfig},
        inference::{InferenceEngine, InferenceService},
        metrics::{AlertManager, MetricsCollector, ModelMonitor},
        model::{ModelFactory, ModelMetadata},
        pipeline::{PipelineBuilder, PipelineOrchestrator},
        registry::{ModelRegistry, RegistryConfig},
        types::*,
        MlService,
    };
    use aiviania::router::Router;
    use aiviania::server::Server;
    use std::collections::HashMap;
    use std::sync::Arc;

    println!("🤖 Starting AIVIANIA AI/ML Example");

    // Example 1: Basic model setup and inference
    println!("\n🧠 Example 1: Basic Model Inference");
    let metadata = ModelMetadata {
        name: "sentiment_analyzer".to_string(),
        version: "1.0.0".to_string(),
        framework: "in_memory".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "input": {"type": "string"}
            }
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "sentiment": {"type": "string"},
                "confidence": {"type": "number"}
            }
        }),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        tags: vec!["nlp".to_string(), "sentiment".to_string()],
    };

    let model = ModelFactory::create_in_memory(metadata);
    let mut model_with_data = model
        .downcast::<aiviania::ai_ml::model::InMemoryModel>()
        .unwrap();
    model_with_data
        .load_from_json(serde_json::json!({
            "positive_words": ["good", "great", "excellent", "awesome"],
            "negative_words": ["bad", "terrible", "awful", "horrible"]
        }))
        .await?;

    let inference_input = InferenceInput {
        data: serde_json::json!({"input": "This is a great product!"}),
        metadata: Some(HashMap::from([("user_id".to_string(), "123".to_string())])),
    };

    let output = model_with_data.predict(inference_input).await?;
    println!("✅ Sentiment Analysis Result: {:?}", output.result);

    // Example 2: Model registry
    println!("\n📚 Example 2: Model Registry");
    let registry_config = RegistryConfig {
        storage_type: "memory".to_string(),
        storage_path: None,
    };
    let registry = ModelRegistry::new(registry_config);

    let model_data = b"dummy model data".to_vec();
    registry
        .register_model(model_with_data.metadata().clone(), model_data)
        .await?;
    println!("✅ Model registered in registry");

    let retrieved_model = registry.get_model("sentiment_analyzer", "1.0.0").await?;
    println!(
        "✅ Retrieved model: {} v{}",
        retrieved_model.metadata.name, retrieved_model.metadata.version
    );

    // Example 3: Inference engine and batch processing
    println!("\n⚡ Example 3: Inference Engine");
    let inference_engine = Arc::new(InferenceEngine::new(5, 10)); // 5 concurrent, 10s timeout
    inference_engine
        .register_model("sentiment_analyzer".to_string(), Box::new(*model_with_data))
        .await?;

    let inference_service = InferenceService::new(inference_engine.clone());

    // Single prediction
    let single_result = inference_service
        .handle_predict(
            "sentiment_analyzer",
            serde_json::json!({"input": "I love this framework!"}),
            None,
        )
        .await?;
    println!("✅ Single prediction: {}", single_result);

    // Batch prediction
    let batch_inputs = vec![
        serde_json::json!({"input": "Amazing experience!"}),
        serde_json::json!({"input": "Could be better"}),
        serde_json::json!({"input": "Absolutely terrible"}),
    ];

    let batch_result = inference_service
        .handle_batch_predict("sentiment_analyzer", batch_inputs, None)
        .await?;
    println!(
        "✅ Batch prediction completed: {} results",
        batch_result["total"]
    );

    // Example 4: ML Pipeline
    println!("\n🔬 Example 4: ML Pipeline");
    let pipeline_orchestrator = PipelineOrchestrator::new();

    // Register model for pipeline
    pipeline_orchestrator
        .register_model(
            "sentiment_analyzer:1.0.0".to_string(),
            Box::new(
                *registry
                    .get_model("sentiment_analyzer", "1.0.0")
                    .await?
                    .metadata()
                    .clone(),
            ),
        )
        .await?;

    // Create pipeline
    let pipeline_config = PipelineBuilder::new("sentiment_pipeline".to_string(), "1.0".to_string())
        .add_step(PipelineStep {
            name: "preprocess".to_string(),
            model_name: "sentiment_analyzer".to_string(),
            model_version: "1.0.0".to_string(),
            input_mapping: HashMap::from([("input".to_string(), "data.input".to_string())]),
            output_mapping: HashMap::from([(
                "sentiment".to_string(),
                "result.sentiment".to_string(),
            )]),
            timeout_ms: Some(5000),
        })
        .input_schema(serde_json::json!({
            "type": "object",
            "properties": {
                "input": {"type": "string"}
            }
        }))
        .output_schema(serde_json::json!({
            "type": "object",
            "properties": {
                "sentiment": {"type": "string"}
            }
        }))
        .build();

    pipeline_orchestrator
        .register_pipeline(pipeline_config)
        .await?;
    pipeline_orchestrator
        .validate_pipeline(
            &pipeline_orchestrator
                .get_pipeline("sentiment_pipeline")
                .await?,
        )
        .await?;

    // Execute pipeline
    let pipeline_input = InferenceInput {
        data: serde_json::json!({"input": "This framework is fantastic!"}),
        metadata: None,
    };

    let pipeline_result = pipeline_orchestrator
        .execute_pipeline("sentiment_pipeline", pipeline_input)
        .await?;
    println!(
        "✅ Pipeline execution: {} steps, {}ms total",
        pipeline_result.steps.len(),
        pipeline_result.total_processing_time_ms
    );

    // Example 5: Metrics and monitoring
    println!("\n📊 Example 5: Metrics & Monitoring");
    let metrics_collector = Arc::new(MetricsCollector::new());
    let model_monitor = ModelMonitor::new(
        metrics_collector.clone(),
        "sentiment_analyzer".to_string(),
        "1.0.0".to_string(),
    );

    // Record some predictions
    for _ in 0..10 {
        let test_output = InferenceOutput {
            result: serde_json::json!({"sentiment": "positive"}),
            confidence: Some(0.9),
            metadata: None,
            processing_time_ms: 150,
        };
        model_monitor
            .record_prediction(&test_output, Some("positive"))
            .await;
    }

    let performance = model_monitor.get_performance().await;
    println!(
        "✅ Model performance: {} predictions",
        performance["total_predictions"]
    );

    // Example 6: ML Service integration
    println!("\n🔧 Example 6: ML Service Integration");
    let ml_config = MlConfig::default();
    let ml_service = MlService::new(ml_config);

    let health = ml_service.health_check().await?;
    println!("✅ ML Service health: {}", health["status"]);

    // Example 7: HTTP endpoints with ML
    println!("\n🌐 Example 7: HTTP ML Endpoints");

    let mut router = Router::new();

    // Single prediction endpoint
    let inference_service_clone = inference_service.clone();
    router.post("/api/ml/predict/:model", move |req| {
        let service = inference_service_clone.clone();
        async move {
            let model_name = req.params().get("model").unwrap_or("default");

            // Parse request body
            let body: serde_json::Value = serde_json::from_slice(req.body())?;

            match service.handle_predict(model_name, body, None).await {
                Ok(result) => aiviania::response::Response::json(&result),
                Err(e) => aiviania::response::Response::json(&serde_json::json!({
                    "error": e.to_string()
                }))
                .with_status(500),
            }
        }
    });

    // Batch prediction endpoint
    let inference_service_clone = inference_service.clone();
    router.post("/api/ml/predict-batch/:model", move |req| {
        let service = inference_service_clone.clone();
        async move {
            let model_name = req.params().get("model").unwrap_or("default");

            // Parse request body as array
            let body: Vec<serde_json::Value> = serde_json::from_slice(req.body())?;

            match service.handle_batch_predict(model_name, body, None).await {
                Ok(result) => aiviania::response::Response::json(&result),
                Err(e) => aiviania::response::Response::json(&serde_json::json!({
                    "error": e.to_string()
                }))
                .with_status(500),
            }
        }
    });

    // Metrics endpoint
    let metrics_clone = metrics_collector.clone();
    router.get("/api/ml/metrics", move |_| {
        let metrics = metrics_clone.clone();
        async move {
            let summary = metrics.get_summary().await;
            aiviania::response::Response::json(&summary)
        }
    });

    // Health endpoint
    let ml_service_clone = ml_service.clone();
    router.get("/api/ml/health", move |_| {
        let service = ml_service_clone.clone();
        async move {
            match service.health_check().await {
                Ok(health) => aiviania::response::Response::json(&health),
                Err(e) => aiviania::response::Response::json(&serde_json::json!({
                    "status": "error",
                    "error": e.to_string()
                }))
                .with_status(500),
            }
        }
    });

    // Create server
    let server = Server::new(router).bind("127.0.0.1:3001");

    println!("🚀 ML Server starting on http://127.0.0.1:3001");
    println!("📖 Try these endpoints:");
    println!("   POST /api/ml/predict/sentiment_analyzer");
    println!("   POST /api/ml/predict-batch/sentiment_analyzer");
    println!("   GET /api/ml/metrics");
    println!("   GET /api/ml/health");
    println!("💡 Example request:");
    println!("   curl -X POST http://127.0.0.1:3001/api/ml/predict/sentiment_analyzer \\");
    println!("        -H 'Content-Type: application/json' \\");
    println!("        -d '{\"input\": \"This is amazing!\"}'");

    println!("\n✅ AI/ML features demonstrated:");
    println!("   ✅ Model registry and versioning");
    println!("   ✅ Inference engine with batch processing");
    println!("   ✅ ML pipelines and orchestration");
    println!("   ✅ Metrics collection and monitoring");
    println!("   ✅ HTTP endpoints for ML predictions");
    println!("   ✅ Health checks and service integration");

    Ok(())
}

#[cfg(not(feature = "ai_ml"))]
fn main() {
    println!("❌ AI/ML feature not enabled. Run with: cargo run --example ai_ml --features ai_ml");
}
