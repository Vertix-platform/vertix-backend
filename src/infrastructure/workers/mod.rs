pub mod multi_chain_listener;
pub mod job_queue;
pub mod ipfs_manager;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
use sqlx::PgPool;

use self::{
    multi_chain_listener::MultiChainListener,
    job_queue::{JobQueue, JobType},
    ipfs_manager::IPFSManager,
};

pub struct WorkerManager {
    blockchain_listener: Option<Arc<RwLock<MultiChainListener>>>,
    job_queue: Option<JobQueue>,
    ipfs_manager: Option<IPFSManager>,
    running: bool,
}

impl WorkerManager {
    pub fn new() -> Self {
        Self {
            blockchain_listener: None,
            job_queue: None,
            ipfs_manager: None,
            running: false,
        }
    }

    pub async fn start(
        &mut self,
        db_pool: PgPool,
        pinata_jwt: String,
        ipfs_gateway: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting worker manager...");

        // Start job queue
        let mut job_queue = JobQueue::new(4);
        job_queue.start().await?;
        self.job_queue = Some(job_queue);

        // Start IPFS manager
        let mut ipfs_manager = IPFSManager::new(pinata_jwt, ipfs_gateway);
        ipfs_manager.start().await?;
        self.ipfs_manager = Some(ipfs_manager);

        // Start multi-chain blockchain listener
        let blockchain_listener = MultiChainListener::new(
            db_pool.clone(),
            tokio::time::Duration::from_secs(15), // Poll every 15 seconds
        )?;

        let blockchain_listener = Arc::new(RwLock::new(blockchain_listener));
        let blockchain_listener_clone = blockchain_listener.clone();

        // Start in background
        tokio::spawn(async move {
            let mut listener = blockchain_listener_clone.write().await;
            if let Err(e) = listener.start().await {
                error!("Blockchain listener failed: {}", e);
            }
        });

        self.blockchain_listener = Some(blockchain_listener);

        info!("Worker manager started successfully");
        Ok(())
    }

    pub async fn start_without_blockchain(
        &mut self,
        // db_pool: PgPool,
        pinata_jwt: String,
        ipfs_gateway: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting worker manager (without blockchain listener)...");

        // Start job queue
        let mut job_queue = JobQueue::new(4);
        job_queue.start().await?;
        self.job_queue = Some(job_queue);

        // Start IPFS manager
        let mut ipfs_manager = IPFSManager::new(pinata_jwt, ipfs_gateway);
        ipfs_manager.start().await?;
        self.ipfs_manager = Some(ipfs_manager);

        info!("Worker manager started successfully (without blockchain listener)");
        Ok(())
    }

    pub async fn stop(&mut self) {
        if !self.running {
            return;
        }

        self.running = false;
        info!("Stopping worker manager...");

        // Stop blockchain listener
        if let Some(listener) = self.blockchain_listener.take() {
            if let Ok(mut listener) = listener.try_write() {
                listener.stop();
            }
        }

        // Stop job queue
        if let Some(mut queue) = self.job_queue.take() {
            queue.stop().await;
        }

        // Stop IPFS manager
        if let Some(mut manager) = self.ipfs_manager.take() {
            manager.stop();
        }

        info!("Worker manager stopped");
    }

    pub async fn enqueue_job(&self, job_type: JobType, payload: serde_json::Value) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
        if let Some(queue) = &self.job_queue {
            queue.enqueue(job_type, payload).await
        } else {
            Err("Job queue not available".into())
        }
    }

    pub async fn upload_metadata(&self, metadata: serde_json::Value) -> Result<String, crate::domain::services::ContractError> {
        if let Some(manager) = &self.ipfs_manager {
            manager.upload_metadata(metadata).await
        } else {
            Err(crate::domain::services::ContractError::ContractCallError("IPFS manager not available".to_string()))
        }
    }

    pub async fn upload_file(&self, file_data: Vec<u8>, filename: String) -> Result<String, crate::domain::services::ContractError> {
        if let Some(manager) = &self.ipfs_manager {
            manager.upload_file(file_data, filename).await
        } else {
            Err(crate::domain::services::ContractError::ContractCallError("IPFS manager not available".to_string()))
        }
    }

    pub async fn get_job_status(&self, job_id: uuid::Uuid) -> Option<self::job_queue::JobStatus> {
        if let Some(queue) = &self.job_queue {
            queue.get_job_status(job_id).await
        } else {
            None
        }
    }

    pub async fn get_jobs(&self) -> Vec<self::job_queue::Job> {
        if let Some(queue) = &self.job_queue {
            queue.get_jobs().await
        } else {
            Vec::new()
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Default for WorkerManager {
    fn default() -> Self {
        Self::new()
    }
}
