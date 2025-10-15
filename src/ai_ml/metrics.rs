//! ML Metrics and monitoring

use super::{types::*, MlResult};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metrics collector for ML operations
pub struct MetricsCollector {
    counters: Arc<RwLock<HashMap<String, u64>>>,
    histograms: Arc<RwLock<HashMap<String, Vec<f64>>>>,
    gauges: Arc<RwLock<HashMap<String, f64>>>,
    start_time: chrono::DateTime<chrono::Utc>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            start_time: chrono::Utc::now(),
        }
    }

    /// Increment a counter
    pub async fn increment_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += value;
    }

    /// Record a histogram value
    pub async fn record_histogram(&self, name: &str, value: f64) {
        let mut histograms = self.histograms.write().await;
        histograms
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(value);
    }

    /// Set a gauge value
    pub async fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write().await;
        gauges.insert(name.to_string(), value);
    }

    /// Record inference metrics
    pub async fn record_inference(&self, model_name: &str, output: &InferenceOutput) {
        // Increment total inferences
        self.increment_counter(&format!("inference.{}.total", model_name), 1)
            .await;

        // Record processing time
        self.record_histogram(
            &format!("inference.{}.processing_time", model_name),
            output.processing_time_ms as f64,
        )
        .await;

        // Record confidence if available
        if let Some(confidence) = output.confidence {
            self.record_histogram(&format!("inference.{}.confidence", model_name), confidence)
                .await;
        }
    }

    /// Record pipeline metrics
    pub async fn record_pipeline(&self, result: &PipelineResult) {
        let pipeline_name = &result.pipeline_name;

        // Increment pipeline executions
        self.increment_counter(&format!("pipeline.{}.executions", pipeline_name), 1)
            .await;

        // Record success/failure
        if result.success {
            self.increment_counter(&format!("pipeline.{}.success", pipeline_name), 1)
                .await;
        } else {
            self.increment_counter(&format!("pipeline.{}.failure", pipeline_name), 1)
                .await;
        }

        // Record total processing time
        self.record_histogram(
            &format!("pipeline.{}.processing_time", pipeline_name),
            result.total_processing_time_ms as f64,
        )
        .await;

        // Record step metrics
        for step in &result.steps {
            let step_name = &step.step_name;
            self.increment_counter(
                &format!("pipeline.{}.step.{}.executions", pipeline_name, step_name),
                1,
            )
            .await;

            if step.success {
                self.increment_counter(
                    &format!("pipeline.{}.step.{}.success", pipeline_name, step_name),
                    1,
                )
                .await;
            } else {
                self.increment_counter(
                    &format!("pipeline.{}.step.{}.failure", pipeline_name, step_name),
                    1,
                )
                .await;
            }

            self.record_histogram(
                &format!(
                    "pipeline.{}.step.{}.processing_time",
                    pipeline_name, step_name
                ),
                step.output.processing_time_ms as f64,
            )
            .await;
        }
    }

    /// Get counter value
    pub async fn get_counter(&self, name: &str) -> u64 {
        let counters = self.counters.read().await;
        counters.get(name).copied().unwrap_or(0)
    }

    /// Get histogram statistics
    pub async fn get_histogram_stats(&self, name: &str) -> Option<HistogramStats> {
        let histograms = self.histograms.read().await;
        histograms.get(name).map(|values| {
            if values.is_empty() {
                return HistogramStats {
                    count: 0,
                    min: 0.0,
                    max: 0.0,
                    mean: 0.0,
                    p50: 0.0,
                    p95: 0.0,
                    p99: 0.0,
                };
            }

            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

            let count = sorted.len();
            let min = sorted[0];
            let max = sorted[count - 1];
            let mean = sorted.iter().sum::<f64>() / count as f64;

            let p50_idx = (count as f64 * 0.5) as usize;
            let p95_idx = (count as f64 * 0.95) as usize;
            let p99_idx = (count as f64 * 0.99) as usize;

            HistogramStats {
                count,
                min,
                max,
                mean,
                p50: sorted[p50_idx.min(count - 1)],
                p95: sorted[p95_idx.min(count - 1)],
                p99: sorted[p99_idx.min(count - 1)],
            }
        })
    }

    /// Get gauge value
    pub async fn get_gauge(&self, name: &str) -> Option<f64> {
        let gauges = self.gauges.read().await;
        gauges.get(name).copied()
    }

    /// Get summary of all metrics
    pub async fn get_summary(&self) -> serde_json::Value {
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;

        let mut histogram_summaries = serde_json::Map::new();
        {
            let histograms = self.histograms.read().await;
            for (name, values) in histograms.iter() {
                if let Some(stats) = self.get_histogram_stats(name).await {
                    histogram_summaries.insert(name.clone(), serde_json::to_value(stats).unwrap());
                }
            }
        }

        serde_json::json!({
            "counters": &*counters,
            "gauges": &*gauges,
            "histograms": histogram_summaries,
            "uptime_seconds": (chrono::Utc::now() - self.start_time).num_seconds()
        })
    }

    /// Reset all metrics
    pub async fn reset(&self) {
        let mut counters = self.counters.write().await;
        let mut histograms = self.histograms.write().await;
        let mut gauges = self.gauges.write().await;

        counters.clear();
        histograms.clear();
        gauges.clear();
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Counters
        let counters = self.counters.read().await;
        for (name, value) in counters.iter() {
            output.push_str(&format!("# HELP {} Counter\n", name));
            output.push_str(&format!("# TYPE {} counter\n", name));
            output.push_str(&format!("{} {}\n", name, value));
        }

        // Gauges
        let gauges = self.gauges.read().await;
        for (name, value) in gauges.iter() {
            output.push_str(&format!("# HELP {} Gauge\n", name));
            output.push_str(&format!("# TYPE {} gauge\n", name));
            output.push_str(&format!("{} {}\n", name, value));
        }

        // Histograms (simplified)
        let histograms = self.histograms.read().await;
        for (name, values) in histograms.iter() {
            if let Some(stats) = self.get_histogram_stats(name).await {
                output.push_str(&format!("# HELP {} Histogram\n", name));
                output.push_str(&format!("# TYPE {} histogram\n", name));
                output.push_str(&format!("{}_count {}\n", name, stats.count));
                output.push_str(&format!("{}_sum {}\n", name, values.iter().sum::<f64>()));
                output.push_str(&format!("{}_bucket{{le=\"+Inf\"}} {}\n", name, stats.count));
            }
        }

        output
    }
}

/// Histogram statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HistogramStats {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

/// Model performance monitor
pub struct ModelMonitor {
    metrics: Arc<MetricsCollector>,
    model_name: String,
    version: String,
}

impl ModelMonitor {
    /// Create a new model monitor
    pub fn new(metrics: Arc<MetricsCollector>, model_name: String, version: String) -> Self {
        Self {
            metrics,
            model_name,
            version,
        }
    }

    /// Record prediction
    pub async fn record_prediction(&self, output: &InferenceOutput, expected_label: Option<&str>) {
        // Record basic metrics
        self.metrics
            .record_inference(&self.model_name, output)
            .await;

        // Record accuracy if expected label provided
        if let (Some(expected), Some(predicted)) = (expected_label, output.result.get("prediction"))
        {
            let correct = predicted == expected;
            let accuracy_key = format!("model.{}.{}.accuracy", self.model_name, self.version);

            if correct {
                self.metrics
                    .increment_counter(&format!("{}_correct", accuracy_key), 1)
                    .await;
            }
            self.metrics
                .increment_counter(&format!("{}_total", accuracy_key), 1)
                .await;
        }
    }

    /// Get model performance metrics
    pub async fn get_performance(&self) -> serde_json::Value {
        let total_predictions = self
            .metrics
            .get_counter(&format!("inference.{}.total", self.model_name))
            .await;
        let processing_time_stats = self
            .metrics
            .get_histogram_stats(&format!("inference.{}.processing_time", self.model_name))
            .await;
        let confidence_stats = self
            .metrics
            .get_histogram_stats(&format!("inference.{}.confidence", self.model_name))
            .await;

        let accuracy_correct = self
            .metrics
            .get_counter(&format!(
                "model.{}.{}.accuracy_correct",
                self.model_name, self.version
            ))
            .await;
        let accuracy_total = self
            .metrics
            .get_counter(&format!(
                "model.{}.{}.accuracy_total",
                self.model_name, self.version
            ))
            .await;
        let accuracy = if accuracy_total > 0 {
            accuracy_correct as f64 / accuracy_total as f64
        } else {
            0.0
        };

        serde_json::json!({
            "model_name": self.model_name,
            "version": self.version,
            "total_predictions": total_predictions,
            "accuracy": accuracy,
            "processing_time_stats": processing_time_stats,
            "confidence_stats": confidence_stats
        })
    }
}

/// Alert manager for ML operations
pub struct AlertManager {
    alerts: Arc<RwLock<Vec<Alert>>>,
    rules: Vec<AlertRule>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(RwLock::new(Vec::new())),
            rules: Vec::new(),
        }
    }

    /// Add an alert rule
    pub fn add_rule(&mut self, rule: AlertRule) {
        self.rules.push(rule);
    }

    /// Check metrics against rules and generate alerts
    pub async fn check_alerts(&self, metrics: &MetricsCollector) {
        for rule in &self.rules {
            if let Some(alert) = rule.check(metrics).await {
                let mut alerts = self.alerts.write().await;
                alerts.push(alert);
            }
        }
    }

    /// Get active alerts
    pub async fn get_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.clone()
    }

    /// Clear resolved alerts
    pub async fn clear_resolved_alerts(&self) {
        let mut alerts = self.alerts.write().await;
        alerts.retain(|alert| !alert.resolved);
    }
}

/// Alert rule
pub struct AlertRule {
    pub name: String,
    pub condition: Box<dyn Fn(&MetricsCollector) -> bool + Send + Sync>,
    pub message: String,
    pub severity: AlertSeverity,
}

impl AlertRule {
    /// Create a new alert rule
    pub fn new<F>(name: String, condition: F, message: String, severity: AlertSeverity) -> Self
    where
        F: Fn(&MetricsCollector) -> bool + Send + Sync + 'static,
    {
        Self {
            name,
            condition: Box::new(condition),
            message,
            severity,
        }
    }

    /// Check if rule triggers an alert
    async fn check(&self, metrics: &MetricsCollector) -> Option<Alert> {
        if (self.condition)(metrics) {
            Some(Alert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_name: self.name.clone(),
                message: self.message.clone(),
                severity: self.severity.clone(),
                timestamp: chrono::Utc::now(),
                resolved: false,
            })
        } else {
            None
        }
    }
}

/// Alert
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_name: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub resolved: bool,
}

/// Alert severity
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}
