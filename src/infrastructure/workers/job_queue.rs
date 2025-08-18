use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use tracing::{info, error, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobType {
    AssetVerification,
    SocialMediaVerification,
    EscrowRelease,
    AuctionEnd,
    CrossChainBridge,
    Notification,
    IPFSUpload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub job_type: JobType,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Retrying,
}

pub struct JobQueue {
    jobs: Arc<RwLock<Vec<Job>>>,
    tx: mpsc::Sender<Job>,
    workers: Vec<tokio::task::JoinHandle<()>>,
    running: bool,
}

impl JobQueue {
    pub fn new(_worker_count: usize) -> Self {
        let (tx, _) = mpsc::channel(1000);
        let jobs = Arc::new(RwLock::new(Vec::new()));

        Self {
            jobs,
            tx,
            workers: Vec::new(),
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting job queue with {} workers", 4);

        // Create a shared channel for all workers
        let (tx, rx) = mpsc::channel(1000);
        self.tx = tx;

        let jobs = self.jobs.clone();

        // Start a single worker that processes jobs
        let worker = tokio::spawn(async move {
            Self::worker_loop(0, jobs, rx).await;
        });

        self.workers.push(worker);

        Ok(())
    }

    pub async fn stop(&mut self) {
        self.running = false;

        // Wait for workers to finish
        for worker in self.workers.drain(..) {
            let _ = worker.await;
        }

        info!("Job queue stopped");
    }

    pub async fn enqueue(&self, job_type: JobType, payload: serde_json::Value) -> Result<Uuid, Box<dyn std::error::Error>> {
        let job = Job {
            id: Uuid::new_v4(),
            job_type: job_type.clone(),
            payload,
            created_at: Utc::now(),
            scheduled_at: None,
            retry_count: 0,
            max_retries: 3,
            status: JobStatus::Pending,
        };

        // Add to jobs list
        {
            let mut jobs = self.jobs.write().await;
            jobs.push(job.clone());
        }

        let _ = self.tx.send(job.clone()).await;

        info!("Enqueued job: {:?} with ID: {}", job_type, job.id);
        Ok(job.id)
    }

    pub async fn enqueue_scheduled(
        &self,
        job_type: JobType,
        payload: serde_json::Value,
        scheduled_at: DateTime<Utc>
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let job = Job {
            id: Uuid::new_v4(),
            job_type: job_type.clone(),
            payload,
            created_at: Utc::now(),
            scheduled_at: Some(scheduled_at),
            retry_count: 0,
            max_retries: 3,
            status: JobStatus::Pending,
        };

        // Add to jobs list
        {
            let mut jobs = self.jobs.write().await;
            jobs.push(job.clone());
        }

        let _ = self.tx.send(job.clone()).await;
        
        info!("Enqueued scheduled job: {:?} with ID: {} for {}", job_type, job.id, scheduled_at);
        Ok(job.id)
    }

    async fn worker_loop(
        worker_id: usize,
        jobs: Arc<RwLock<Vec<Job>>>,
        mut rx: mpsc::Receiver<Job>,
    ) {
        info!("Worker {} started", worker_id);
        
        while let Some(mut job) = rx.recv().await {
            debug!("Worker {} processing job: {:?}", worker_id, job.id);
            
            job.status = JobStatus::Running;
            Self::update_job_status(&jobs, &job).await;
            
            let result = Self::process_job(&job).await;
            
            match result {
                Ok(_) => {
                    job.status = JobStatus::Completed;
                    info!("Worker {} completed job: {:?}", worker_id, job.id);
                }
                Err(e) => {
                    error!("Worker {} failed job: {:?} with error: {}", worker_id, job.id, e);
                    
                    if job.retry_count < job.max_retries {
                        job.retry_count += 1;
                        job.status = JobStatus::Retrying;
                        info!("Worker {} retrying job: {:?} (attempt {}/{})", worker_id, job.id, job.retry_count, job.max_retries);
                    } else {
                        job.status = JobStatus::Failed;
                        error!("Worker {} failed job: {:?} after {} retries", worker_id, job.id, job.max_retries);
                    }
                }
            }
            
            Self::update_job_status(&jobs, &job).await;
        }
        
        info!("Worker {} stopped", worker_id);
    }

    async fn process_job(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &job.job_type {
            JobType::AssetVerification => {
                Self::process_asset_verification(job).await?;
            }
            JobType::SocialMediaVerification => {
                Self::process_social_media_verification(job).await?;
            }
            JobType::EscrowRelease => {
                Self::process_escrow_release(job).await?;
            }
            JobType::AuctionEnd => {
                Self::process_auction_end(job).await?;
            }
            JobType::CrossChainBridge => {
                Self::process_cross_chain_bridge(job).await?;
            }
            JobType::Notification => {
                Self::process_notification(job).await?;
            }
            JobType::IPFSUpload => {
                Self::process_ipfs_upload(job).await?;
            }
        }
        
        Ok(())
    }

    async fn process_asset_verification(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing asset verification job: {:?}", job.id);
        // TODO: Implement asset verification logic
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        Ok(())
    }

    async fn process_social_media_verification(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing social media verification job: {:?}", job.id);
        // TODO: Implement social media verification logic
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        Ok(())
    }

    async fn process_escrow_release(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing escrow release job: {:?}", job.id);
        // TODO: Implement escrow release logic
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        Ok(())
    }

    async fn process_auction_end(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing auction end job: {:?}", job.id);
        // TODO: Implement auction end logic
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        Ok(())
    }

    async fn process_cross_chain_bridge(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing cross-chain bridge job: {:?}", job.id);
        // TODO: Implement cross-chain bridge logic
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        Ok(())
    }

    async fn process_notification(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing notification job: {:?}", job.id);
        // TODO: Implement notification logic
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        Ok(())
    }

    async fn process_ipfs_upload(job: &Job) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Processing IPFS upload job: {:?}", job.id);
        // TODO: Implement IPFS upload logic
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        Ok(())
    }

    async fn update_job_status(jobs: &Arc<RwLock<Vec<Job>>>, updated_job: &Job) {
        let mut jobs = jobs.write().await;
        if let Some(job) = jobs.iter_mut().find(|j| j.id == updated_job.id) {
            *job = updated_job.clone();
        }
    }

    pub async fn get_job_status(&self, job_id: Uuid) -> Option<JobStatus> {
        let jobs = self.jobs.read().await;
        jobs.iter().find(|j| j.id == job_id).map(|j| j.status.clone())
    }

    pub async fn get_jobs(&self) -> Vec<Job> {
        let jobs = self.jobs.read().await;
        jobs.clone()
    }
}
