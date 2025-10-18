//! Example demonstrating background jobs and queue system in AIVIANIA
//!
//! This example shows how to use the job queue system with different
//! storage backends and custom job handlers.

use aiviania::jobs::{helpers::*, Job, JobManager, JobWorker, MemoryJobQueue};
use async_trait::async_trait;
use std::sync::Arc;

/// Example email sending job handler
struct EmailHandler;

#[async_trait]
impl aiviania::jobs::JobHandler for EmailHandler {
    async fn execute(&self, job: &mut Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload: serde_json::Value = serde_json::from_value(job.payload.clone())?;

        println!("📧 Sending email to: {}", payload["to"]);
        println!("   Subject: {}", payload["subject"]);
        println!("   Body: {}", payload["body"]);

        // Simulate email sending delay
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        println!("✅ Email sent successfully!");
        Ok(())
    }
}

/// Example data processing job handler
struct DataProcessor;

#[async_trait]
impl aiviania::jobs::JobHandler for DataProcessor {
    async fn execute(&self, job: &mut Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload: serde_json::Value = serde_json::from_value(job.payload.clone())?;

        println!("🔄 Processing data: {}", payload["data_id"]);
        println!("   Operation: {}", payload["operation"]);

        // Simulate processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        println!("✅ Data processing completed!");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 AIVIANIA Background Jobs Example");
    println!("====================================");

    // Create job queue (using memory store for this example)
    let queue = Arc::new(MemoryJobQueue::new());

    // Create job manager
    let manager = JobManager::new(queue.clone());

    // Create workers with handlers
    let email_worker = JobWorker::new(queue.clone()).register_handler("send_email", EmailHandler);

    let data_worker = JobWorker::new(queue.clone()).register_handler("process_data", DataProcessor);

    // Add workers to manager
    let manager = manager.add_worker(email_worker).add_worker(data_worker);

    // Start workers in background - clone manager by wrapping in Arc for sharing
    let manager_arc = Arc::new(manager);
    let manager_clone = Arc::clone(&manager_arc);
    tokio::spawn(async move {
        if let Err(e) = manager_clone.start_workers(&["default"]).await {
            eprintln!("Worker error: {}", e);
        }
    });

    // Give workers time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    println!("\n📋 Enqueueing jobs...");

    // Enqueue some jobs
    let email_job_id = manager_arc
        .enqueue(
            "send_email",
            serde_json::json!({
                "to": "user@example.com",
                "subject": "Welcome to AIVIANIA!",
                "body": "Thank you for using our framework."
            }),
        )
        .await?;

    println!("📧 Email job enqueued: {}", email_job_id);

    let data_job_id = manager_arc
        .enqueue(
            "process_data",
            serde_json::json!({
                "data_id": "user_123",
                "operation": "validate"
            }),
        )
        .await?;

    println!("🔄 Data processing job enqueued: {}", data_job_id);

    // Enqueue jobs using helper functions
    let helper_email_job = create_email_job(
        "admin@example.com",
        "System Alert",
        "Background job system is working!",
    );
    let helper_email_id = manager_arc.enqueue_job(helper_email_job).await?;
    println!("📧 Helper email job enqueued: {}", helper_email_id);

    let helper_data_job = create_data_processing_job("batch_001", "analyze");
    let helper_data_id = manager_arc.enqueue_job(helper_data_job).await?;
    println!("🔄 Helper data job enqueued: {}", helper_data_id);

    // Wait for jobs to be processed
    println!("\n⏳ Waiting for jobs to complete...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Check job statuses
    println!("\n📊 Job Status Summary:");
    let jobs = vec![email_job_id, data_job_id, helper_email_id, helper_data_id];

    for job_id in jobs {
        if let Ok(Some(job)) = manager_arc.get_job(&job_id).await {
            println!("Job {}: {:?}", job_id, job.status);
        }
    }

    // Check queue status
    let pending_count = manager_arc.pending_count("default").await?;
    println!("\n📈 Pending jobs in queue: {}", pending_count);

    println!("\n✨ Background jobs example completed!");
    println!("💡 In production, use RedisJobQueue with --features redis");

    Ok(())
}
