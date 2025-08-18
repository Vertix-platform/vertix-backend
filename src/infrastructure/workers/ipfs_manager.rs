use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use tracing::{info, error, debug};
use crate::domain::services::ContractError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPFSUploadJob {
    pub id: String,
    pub metadata: serde_json::Value,
    pub file_path: Option<String>,
    pub file_data: Option<Vec<u8>>,
    pub retry_count: u32,
    pub max_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPFSUploadResult {
    pub job_id: String,
    pub ipfs_hash: String,
    pub ipfs_url: String,
    pub success: bool,
    pub error: Option<String>,
}

pub struct IPFSManager {
    pinata_jwt: String,
    ipfs_gateway: String,
    client: Client,
    upload_queue: Arc<RwLock<Vec<IPFSUploadJob>>>,
    results: Arc<RwLock<Vec<IPFSUploadResult>>>,
    tx: mpsc::Sender<IPFSUploadJob>,
    running: bool,
}

impl IPFSManager {
    pub fn new(pinata_jwt: String, ipfs_gateway: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let (tx, _) = mpsc::channel(1000);

        Self {
            pinata_jwt,
            ipfs_gateway,
            client,
            upload_queue: Arc::new(RwLock::new(Vec::new())),
            results: Arc::new(RwLock::new(Vec::new())),
            tx,
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting IPFS manager...");

        // Create a new channel for the worker
        let (tx, rx) = mpsc::channel(1000);
        let upload_queue = self.upload_queue.clone();
        let results = self.results.clone();
        let pinata_jwt = self.pinata_jwt.clone();
        let ipfs_gateway = self.ipfs_gateway.clone();
        let client = self.client.clone();

        // Update the sender
        self.tx = tx;

        tokio::spawn(async move {
            Self::upload_worker(rx, upload_queue, results, pinata_jwt, ipfs_gateway, client).await;
        });

        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
        info!("Stopping IPFS manager...");
    }

    pub async fn upload_metadata(&self, metadata: serde_json::Value) -> Result<String, ContractError> {
        let job_id = uuid::Uuid::new_v4().to_string();
        
        let job = IPFSUploadJob {
            id: job_id.clone(),
            metadata,
            file_path: None,
            file_data: None,
            retry_count: 0,
            max_retries: 3,
        };

        // Add to queue
        {
            let mut queue = self.upload_queue.write().await;
            queue.push(job.clone());
        }

        // Send to worker
        if let Err(e) = self.tx.send(job).await {
            return Err(ContractError::ContractCallError(format!("Failed to queue upload job: {}", e)));
        }

        info!("Queued metadata upload job: {}", job_id);
        
        // Wait for result
        self.wait_for_result(&job_id).await
    }

    pub async fn upload_file(&self, file_data: Vec<u8>, filename: String) -> Result<String, ContractError> {
        let job_id = uuid::Uuid::new_v4().to_string();
        
        let job = IPFSUploadJob {
            id: job_id.clone(),
            metadata: serde_json::json!({}),
            file_path: Some(filename),
            file_data: Some(file_data),
            retry_count: 0,
            max_retries: 3,
        };

        // Add to queue
        {
            let mut queue = self.upload_queue.write().await;
            queue.push(job.clone());
        }

        // Send to worker
        if let Err(e) = self.tx.send(job).await {
            return Err(ContractError::ContractCallError(format!("Failed to queue upload job: {}", e)));
        }

        info!("Queued file upload job: {}", job_id);
        
        // Wait for result
        self.wait_for_result(&job_id).await
    }

    async fn wait_for_result(&self, job_id: &str) -> Result<String, ContractError> {
        let mut attempts = 0;
        let max_attempts = 60; // Wait up to 60 seconds
        
        while attempts < max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            
            let results = self.results.read().await;
            if let Some(result) = results.iter().find(|r| r.job_id == job_id) {
                if result.success {
                    return Ok(result.ipfs_hash.clone());
                } else {
                    return Err(ContractError::ContractCallError(
                        result.error.clone().unwrap_or_else(|| "Upload failed".to_string())
                    ));
                }
            }
            
            attempts += 1;
        }
        
        Err(ContractError::ContractCallError("Upload timeout".to_string()))
    }

    async fn upload_worker(
        mut rx: mpsc::Receiver<IPFSUploadJob>,
        upload_queue: Arc<RwLock<Vec<IPFSUploadJob>>>,
        results: Arc<RwLock<Vec<IPFSUploadResult>>>,
        pinata_jwt: String,
        ipfs_gateway: String,
        client: Client,
    ) {
        info!("IPFS upload worker started");
        
        while let Some(job) = rx.recv().await {
            debug!("Processing upload job: {}", job.id);
            
            let result = Self::process_upload_job(&job, &pinata_jwt, &ipfs_gateway, &client).await;
            
            // Store result
            {
                let mut results = results.write().await;
                results.push(result);
            }
            
            // Remove from queue
            {
                let mut queue = upload_queue.write().await;
                queue.retain(|j| j.id != job.id);
            }
        }
        
        info!("IPFS upload worker stopped");
    }

    async fn process_upload_job(
        job: &IPFSUploadJob,
        pinata_jwt: &str,
        ipfs_gateway: &str,
        client: &Client,
    ) -> IPFSUploadResult {
        let mut retry_count = job.retry_count;
        
        while retry_count < job.max_retries {
            match Self::upload_to_pinata(job, pinata_jwt, client).await {
                Ok(ipfs_hash) => {
                    let ipfs_url = format!("{}/{}", ipfs_gateway, ipfs_hash);
                    
                    info!("Successfully uploaded to IPFS: {} -> {}", job.id, ipfs_hash);
                    
                    return IPFSUploadResult {
                        job_id: job.id.clone(),
                        ipfs_hash,
                        ipfs_url,
                        success: true,
                        error: None,
                    };
                }
                Err(e) => {
                    retry_count += 1;
                    error!("Upload failed for job {} (attempt {}/{}): {}", job.id, retry_count, job.max_retries, e);
                    
                    if retry_count >= job.max_retries {
                        return IPFSUploadResult {
                            job_id: job.id.clone(),
                            ipfs_hash: String::new(),
                            ipfs_url: String::new(),
                            success: false,
                            error: Some(e.to_string()),
                        };
                    }
                    
                    // Wait before retry
                    tokio::time::sleep(tokio::time::Duration::from_secs(2u64.pow(retry_count))).await;
                }
            }
        }
        
        IPFSUploadResult {
            job_id: job.id.clone(),
            ipfs_hash: String::new(),
            ipfs_url: String::new(),
            success: false,
            error: Some("Max retries exceeded".to_string()),
        }
    }

    async fn upload_to_pinata(
        job: &IPFSUploadJob,
        pinata_jwt: &str,
        client: &Client,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Check if we're in test mode
        if pinata_jwt == "test_jwt" {
            // Generate mock IPFS hash for testing
            let mock_hash = format!("Qm{}", hex::encode(&job.id.as_bytes()[..20]));
            return Ok(mock_hash);
        }

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", pinata_jwt))?
        );

        let mut form = reqwest::multipart::Form::new();

        if let Some(file_data) = &job.file_data {
            // Upload file
            let file_part = reqwest::multipart::Part::bytes(file_data.clone())
                .file_name(job.file_path.as_ref().unwrap_or(&"file".to_string()).clone())
                .mime_str("application/octet-stream")?;
            
            form = form.part("file", file_part);
        } else {
            // Upload metadata
            let metadata_string = serde_json::to_string(&job.metadata)?;
            let metadata_part = reqwest::multipart::Part::text(metadata_string)
                .file_name(format!("{}.json", job.id))
                .mime_str("application/json")?;
            
            form = form.part("file", metadata_part);
        }

        // Set to "public" for public upload
        let network_part = reqwest::multipart::Part::text("public");
        form = form.part("network", network_part);

        let response = client
            .post("https://uploads.pinata.cloud/v3/files")
            .headers(headers)
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Pinata upload failed: {}", error_text).into());
        }

        let pinata_response: PinataResponse = response.json().await?;
        Ok(pinata_response.data.cid)
    }

    pub async fn get_upload_status(&self, job_id: &str) -> Option<IPFSUploadResult> {
        let results = self.results.read().await;
        results.iter().find(|r| r.job_id == job_id).cloned()
    }

    pub async fn get_pending_uploads(&self) -> Vec<IPFSUploadJob> {
        let queue = self.upload_queue.read().await;
        queue.clone()
    }
}

#[derive(Debug, Deserialize)]
struct PinataResponse {
    data: PinataData,
}

#[derive(Debug, Deserialize)]
struct PinataData {
    cid: String,
}
