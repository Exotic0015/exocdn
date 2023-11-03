use std::sync::Arc;

use ahash::RandomState;
use axum::BoxError;
use dashmap::DashMap;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::task::JoinSet;
use tracing::info;
use walkdir::WalkDir;

use crate::CdnSettings;

/// Application state structure, including a hash lock and content directory
pub struct CdnAppState {
    pub hasharc: Arc<DashMap<String, String, RandomState>>,
    pub config: CdnSettings,
}

impl CdnAppState {
    pub async fn new(config: CdnSettings) -> Result<Self, BoxError> {
        let hasharc = Arc::new(DashMap::with_hasher(RandomState::new()));

        let state = Self { hasharc, config };

        // Calculate file hashes and populate the hashmap
        state.calculate_hashes().await?;

        // Create and return the application state
        Ok(state)
    }

    /// Populate the file hash map with blake3 hashes
    async fn calculate_hashes(&self) -> Result<(), BoxError> {
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
        let mut handles = JoinSet::new();
        for entry in files {
            let hasharc = self.hasharc.clone();
            let content_dir = self.config.content_dir.clone();

            handles.spawn(async move {
                let path = entry.path();

                let mut file = File::open(path).await?;
                let mut file_buffer = Vec::new();
                file.read_to_end(&mut file_buffer).await?;

                let hash = blake3::hash(&file_buffer).to_string();
                let filename = path.strip_prefix(content_dir)?.to_string_lossy();

                info!("{}/{}", hash, filename);
                hasharc.insert(filename.into_owned(), hash);

                Result::<(), BoxError>::Ok(())
            });
        }

        // Wait for all tasks to complete
        while let Some(res) = handles.join_next().await {
            if let Err(err) = res? {
                panic!("Hash calculation failed: {err}");
            }
        }

        info!("Done calculating file hashes.");
        Ok(())
    }
}
