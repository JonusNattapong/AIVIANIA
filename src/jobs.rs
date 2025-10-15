//! Background jobs and queue system.
//!
//! Provides asynchronous job processing with Redis-backed queues and worker management.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Job priority levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

/// Job definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub priority: JobPriority,
    pub status: JobStatus,
    pub max_attempts: u32,
    pub attempts: u32,
    pub created_at: DateTime<Utc>,
    pub scheduled_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub queue_name: String,
}

impl Job {
    /// Create a new job
    pub fn new<T: Serialize>(job_type: &str, payload: T) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            job_type: job_type.to_string(),
            payload: serde_json::to_value(payload).unwrap(),
            priority: JobPriority::Normal,
            status: JobStatus::Pending,
            max_attempts: 3,
            attempts: 0,
            created_at: Utc::now(),
            scheduled_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
            queue_name: "default".to_string(),
        }
    }

    /// Set job priority
    pub fn with_priority(mut self, priority: JobPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set maximum attempts
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Set queue name
    pub fn with_queue(mut self, queue_name: &str) -> Self {
        self.queue_name = queue_name.to_string();
        self
    }

    /// Schedule job for later execution
    pub fn schedule_at(mut self, scheduled_at: DateTime<Utc>) -> Self {
        self.scheduled_at = scheduled_at;
        self
    }

    /// Schedule job with delay
    pub fn delay(mut self, duration: Duration) -> Self {
        self.scheduled_at = Utc::now() + duration;
        self
    }

    /// Check if job is ready to be processed
    pub fn is_ready(&self) -> bool {
        self.status == JobStatus::Pending && Utc::now() >= self.scheduled_at
    }

    /// Check if job can be retried
    pub fn can_retry(&self) -> bool {
        self.attempts < self.max_attempts
    }

    /// Mark job as started
    pub fn mark_started(&mut self) {
        self.status = JobStatus::Processing;
        self.started_at = Some(Utc::now());
        self.attempts += 1;
    }

    /// Mark job as completed
    pub fn mark_completed(&mut self) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(Utc::now());
    }

    /// Mark job as failed
    pub fn mark_failed(&mut self, error: &str) {
        self.status = JobStatus::Failed;
        self.error_message = Some(error.to_string());
    }
}

/// Job handler trait
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Execute the job
    async fn execute(&self, job: &mut Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Queue interface for job storage and retrieval
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Enqueue a job
    async fn enqueue(&self, job: Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Dequeue a job from a specific queue
    async fn dequeue(
        &self,
        queue_name: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get job by ID
    async fn get_job(
        &self,
        job_id: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>>;

    /// Update job status
    async fn update_job(&self, job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Get pending jobs count for a queue
    async fn pending_count(
        &self,
        queue_name: &str,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Clean up old completed/failed jobs
    async fn cleanup(
        &self,
        older_than: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory job queue for development/testing
pub struct MemoryJobQueue {
    jobs: Arc<RwLock<HashMap<String, Job>>>,
    queues: Arc<RwLock<HashMap<String, Vec<String>>>>, // queue_name -> job_ids
}

impl MemoryJobQueue {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            queues: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl JobQueue for MemoryJobQueue {
    async fn enqueue(&self, job: Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let job_id = job.id.clone();
        let queue_name = job.queue_name.clone();

        let mut jobs = self.jobs.write().await;
        let mut queues = self.queues.write().await;

        jobs.insert(job_id.clone(), job);
        queues
            .entry(queue_name)
            .or_insert_with(Vec::new)
            .push(job_id);

        Ok(())
    }

    async fn dequeue(
        &self,
        queue_name: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>> {
        let mut queues = self.queues.write().await;
        let mut jobs = self.jobs.write().await;

        if let Some(queue) = queues.get_mut(queue_name) {
            while let Some(job_id) = queue.pop() {
                if let Some(job) = jobs.get_mut(&job_id) {
                    if job.is_ready() {
                        let mut job = job.clone();
                        job.mark_started();
                        jobs.insert(job_id, job.clone());
                        return Ok(Some(job));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn get_job(
        &self,
        job_id: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(job_id).cloned())
    }

    async fn update_job(&self, job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut jobs = self.jobs.write().await;
        jobs.insert(job.id.clone(), job.clone());
        Ok(())
    }

    async fn pending_count(
        &self,
        queue_name: &str,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let queues = self.queues.read().await;
        let jobs = self.jobs.read().await;

        if let Some(queue) = queues.get(queue_name) {
            let count = queue
                .iter()
                .filter(|job_id| {
                    jobs.get(*job_id)
                        .map(|job| job.status == JobStatus::Pending)
                        .unwrap_or(false)
                })
                .count();
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    async fn cleanup(
        &self,
        _older_than: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut jobs = self.jobs.write().await;
        let mut queues = self.queues.write().await;

        // Remove completed and failed jobs older than the specified duration
        let cutoff = Utc::now() - _older_than;
        jobs.retain(|_, job| {
            if (job.status == JobStatus::Completed || job.status == JobStatus::Failed)
                && job.completed_at.map(|t| t < cutoff).unwrap_or(false)
            {
                // Remove from queues
                if let Some(queue) = queues.get_mut(&job.queue_name) {
                    queue.retain(|id| id != &job.id);
                }
                false
            } else {
                true
            }
        });

        Ok(())
    }
}

/// Redis-backed job queue for production
#[cfg(feature = "redis")]
pub struct RedisJobQueue {
    client: redis::Client,
}

#[cfg(feature = "redis")]
impl RedisJobQueue {
    pub fn new(redis_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }

    fn queue_key(queue_name: &str) -> String {
        format!("queue:{}", queue_name)
    }

    fn job_key(job_id: &str) -> String {
        format!("job:{}", job_id)
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl JobQueue for RedisJobQueue {
    async fn enqueue(&self, job: Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let queue_key = Self::queue_key(&job.queue_name);
        let job_key = Self::job_key(&job.id);
        let job_data = serde_json::to_string(&job)?;

        redis::pipe()
            .set(&job_key, &job_data)
            .zadd(&queue_key, &job.id, job.priority as i32)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    async fn dequeue(
        &self,
        queue_name: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let queue_key = Self::queue_key(queue_name);

        // Get the highest priority job (lowest score first)
        let job_ids: Vec<String> = redis::cmd("ZRANGE")
            .arg(&queue_key)
            .arg(0)
            .arg(0)
            .query_async(&mut conn)
            .await?;

        if let Some(job_id) = job_ids.first() {
            let job_key = Self::job_key(job_id);
            let job_data: Option<String> = redis::cmd("GET")
                .arg(&job_key)
                .query_async(&mut conn)
                .await?;

            if let Some(data) = job_data {
                let mut job: Job = serde_json::from_str(&data)?;
                if job.is_ready() {
                    // Remove from queue and update job
                    redis::pipe()
                        .zrem(&queue_key, job_id)
                        .query_async(&mut conn)
                        .await?;

                    job.mark_started();
                    let updated_data = serde_json::to_string(&job)?;
                    redis::cmd("SET")
                        .arg(&job_key)
                        .arg(&updated_data)
                        .query_async(&mut conn)
                        .await?;

                    return Ok(Some(job));
                }
            }
        }

        Ok(None)
    }

    async fn get_job(
        &self,
        job_id: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let job_key = Self::job_key(job_id);
        let job_data: Option<String> = redis::cmd("GET")
            .arg(&job_key)
            .query_async(&mut conn)
            .await?;

        match job_data {
            Some(data) => {
                let job: Job = serde_json::from_str(&data)?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    async fn update_job(&self, job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let job_key = Self::job_key(&job.id);
        let job_data = serde_json::to_string(job)?;
        redis::cmd("SET")
            .arg(&job_key)
            .arg(&job_data)
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    async fn pending_count(
        &self,
        queue_name: &str,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let queue_key = Self::queue_key(queue_name);
        let count: u64 = redis::cmd("ZCARD")
            .arg(&queue_key)
            .query_async(&mut conn)
            .await?;
        Ok(count)
    }

    async fn cleanup(
        &self,
        older_than: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.client.get_async_connection().await?;
        let cutoff = Utc::now() - older_than;

        // Find all job keys
        let job_keys: Vec<String> = redis::cmd("KEYS")
            .arg("job:*")
            .query_async(&mut conn)
            .await?;

        for job_key in job_keys {
            let job_data: Option<String> = redis::cmd("GET")
                .arg(&job_key)
                .query_async(&mut conn)
                .await?;

            if let Some(data) = job_data {
                if let Ok(job) = serde_json::from_str::<Job>(&data) {
                    if (job.status == JobStatus::Completed || job.status == JobStatus::Failed)
                        && job.completed_at.map(|t| t < cutoff).unwrap_or(false)
                    {
                        // Remove job and from any queues
                        redis::pipe()
                            .del(&job_key)
                            .zrem(&Self::queue_key(&job.queue_name), &job.id)
                            .query_async(&mut conn)
                            .await?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Job worker for processing jobs
pub struct JobWorker {
    queue: Arc<dyn JobQueue>,
    handlers: HashMap<String, Arc<dyn JobHandler>>,
    concurrency: usize,
}

impl JobWorker {
    /// Create a new job worker
    pub fn new(queue: Arc<dyn JobQueue>) -> Self {
        Self {
            queue,
            handlers: HashMap::new(),
            concurrency: 1,
        }
    }

    /// Set concurrency level
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Register a job handler
    pub fn register_handler<H: JobHandler + 'static>(mut self, job_type: &str, handler: H) -> Self {
        self.handlers
            .insert(job_type.to_string(), Arc::new(handler));
        self
    }

    /// Start the worker
    pub async fn start(
        &self,
        queue_names: &[&str],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create a channel for each worker
        let mut senders = Vec::new();
        let mut receivers = Vec::new();

        for _ in 0..self.concurrency {
            let (tx, rx) = mpsc::channel::<Job>(1);
            senders.push(tx);
            receivers.push(rx);
        }

        // Spawn worker tasks
        let mut handles = Vec::new();
        for mut rx in receivers {
            let handlers = self.handlers.clone();

            let handle = tokio::spawn(async move {
                while let Some(mut job) = rx.recv().await {
                    if let Some(handler) = handlers.get(&job.job_type) {
                        match handler.execute(&mut job).await {
                            Ok(_) => {
                                job.mark_completed();
                            }
                            Err(e) => {
                                job.mark_failed(&e.to_string());
                            }
                        }

                        // Note: In a real implementation, you'd update the job status in the queue
                        // For now, we just process it
                    }
                }
            });

            handles.push(handle);
        }

        // Job polling loop
        let queue_names: Vec<String> = queue_names.iter().map(|s| s.to_string()).collect();
        loop {
            for queue_name in &queue_names {
                if let Ok(Some(job)) = self.queue.dequeue(queue_name).await {
                    // Send to first available worker
                    for sender in &senders {
                        match sender.try_send(job.clone()) {
                            Ok(_) => break,                                        // Successfully sent
                            Err(mpsc::error::TrySendError::Full(_)) => continue, // Try next worker
                            Err(mpsc::error::TrySendError::Closed(_)) => continue, // Worker closed
                        }
                    }
                }
            }

            // Small delay to prevent busy polling
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
}

/// Job manager for high-level job operations
pub struct JobManager {
    queue: Arc<dyn JobQueue>,
    workers: Vec<JobWorker>,
}

impl JobManager {
    /// Create a new job manager
    pub fn new(queue: Arc<dyn JobQueue>) -> Self {
        Self {
            queue,
            workers: Vec::new(),
        }
    }

    /// Add a worker
    pub fn add_worker(mut self, worker: JobWorker) -> Self {
        self.workers.push(worker);
        self
    }

    /// Enqueue a job
    pub async fn enqueue<T: Serialize>(
        &self,
        job_type: &str,
        payload: T,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let job = Job::new(job_type, payload);
        let job_id = job.id.clone();
        self.queue.enqueue(job).await?;
        Ok(job_id)
    }

    /// Enqueue a job with custom options
    pub async fn enqueue_job(
        &self,
        job: Job,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let job_id = job.id.clone();
        self.queue.enqueue(job).await?;
        Ok(job_id)
    }

    /// Get job status
    pub async fn get_job(
        &self,
        job_id: &str,
    ) -> Result<Option<Job>, Box<dyn std::error::Error + Send + Sync>> {
        self.queue.get_job(job_id).await
    }

    /// Get pending jobs count
    pub async fn pending_count(
        &self,
        queue_name: &str,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        self.queue.pending_count(queue_name).await
    }

    /// Start all workers
    pub async fn start_workers(
        &self,
        queue_names: &[&str],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut handles = Vec::new();
        let queue_names: Vec<String> = queue_names.iter().map(|s| s.to_string()).collect();

        for worker in &self.workers {
            let queue_names = queue_names.clone();
            let worker = worker.clone();
            let handle = tokio::spawn(async move {
                worker
                    .start(&queue_names.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                    .await
            });
            handles.push(handle);
        }

        // Wait for all workers (this will run indefinitely)
        join_all(handles).await;
        Ok(())
    }

    /// Clean up old jobs
    pub async fn cleanup(
        &self,
        older_than: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.queue.cleanup(older_than).await
    }
}

impl Clone for JobWorker {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            handlers: self.handlers.clone(),
            concurrency: self.concurrency,
        }
    }
}

/// Helper functions for common job patterns
pub mod helpers {
    use super::*;

    /// Create an email sending job
    pub fn create_email_job(to: &str, subject: &str, body: &str) -> Job {
        let payload = serde_json::json!({
            "to": to,
            "subject": subject,
            "body": body
        });

        Job::new("send_email", payload).with_priority(JobPriority::Normal)
    }

    /// Create a data processing job
    pub fn create_data_processing_job(data_id: &str, operation: &str) -> Job {
        let payload = serde_json::json!({
            "data_id": data_id,
            "operation": operation
        });

        Job::new("process_data", payload).with_priority(JobPriority::High)
    }

    /// Create a cleanup job
    pub fn create_cleanup_job(resource_type: &str) -> Job {
        let payload = serde_json::json!({
            "resource_type": resource_type
        });

        Job::new("cleanup", payload)
            .with_priority(JobPriority::Low)
            .delay(Duration::hours(24)) // Run daily
    }
}
