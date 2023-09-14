use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use tracing::info;
use walkdir::WalkDir;

use crate::CdnSettings;

/// Application state structure, including a hash lock and content directory
pub struct CdnAppState {
    pub hasharc: Arc<RwLock<HashMap<String, String>>>,
    pub config: CdnSettings,
}

impl CdnAppState {
    pub async fn new(config: CdnSettings) -> Result<Self, Box<dyn Error>> {
        let hasharc = Arc::new(RwLock::new(HashMap::new()));

        let state = CdnAppState { hasharc, config };

        // Calculate file hashes and populate the hashmap
        state.calculate_hashes().await?;

        // Create and return the application state
        Ok(state)
    }

    /// Populate the file hash map with blake3 hashes
    async fn calculate_hashes(&self) -> Result<(), Box<dyn Error>> {
        info!("Calculating CDN file hashes...");
        let mut files: Vec<walkdir::DirEntry> = Vec::new();

        // Get available files using WalkDir
        for entry in WalkDir::new(&self.config.content_dir) {
            let entry = entry?;
            let filetype = entry.file_type();
            if filetype.is_file() {
                files.push(entry);
            }
        }

        // Spawn a task for every file which calculates and stores the hash
        let mut handles = Vec::new();
        for entry in files {
            let hasharc = self.hasharc.clone();
            let content_dir = self.config.content_dir.clone();

            let handle = tokio::spawn(async move {
                let path = entry.path();

                let mut file = File::open(path).await?;
                let mut file_buffer = Vec::new();
                file.read_to_end(&mut file_buffer).await?;

                let hash = blake3::hash(&file_buffer).to_string();

                let filename = path
                    .strip_prefix(content_dir)?
                    .to_string_lossy()
                    .to_string();

                info!("{}/{}", hash, filename);

                hasharc.write().await.insert(filename, hash);

                Result::<_, Box<dyn Error + Send + Sync>>::Ok(())
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        futures::future::try_join_all(handles).await?;

        info!("Done calculating file hashes.");
        Ok(())
    }
}
