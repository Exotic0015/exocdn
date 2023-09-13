use crate::CdnSettings;
use rayon::prelude::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, RwLock};
use tracing::info;
use walkdir::WalkDir;

/// Application state structure, including a hash lock and content directory
pub struct CdnAppState {
    pub hasharc: Arc<RwLock<HashMap<String, String>>>,
    pub config: CdnSettings,
}

impl CdnAppState {
    pub fn new(config: CdnSettings) -> Result<Self, Box<dyn Error>> {
        let hasharc = Arc::new(RwLock::new(HashMap::new()));

        let state = CdnAppState { hasharc, config };

        // Calculate file hashes and populate the hashmap
        state.calculate_hashes()?;

        // Create and return the application state
        Ok(state)
    }

    fn calculate_hashes(&self) -> Result<(), Box<dyn Error>> {
        info!("Calculating file hashes...");
        let mut files: Vec<walkdir::DirEntry> = Vec::new();

        for entry in WalkDir::new(&self.config.content_dir) {
            let entry = entry?;
            let filetype = entry.file_type();
            if filetype.is_file() {
                files.push(entry);
            }
        }

        files.par_iter().for_each(|entry| {
            let path = entry.path();

            let mut file = File::open(path).unwrap();
            let mut file_contents = Vec::new();
            file.read_to_end(&mut file_contents).unwrap();

            let hash = blake3::hash(&file_contents).to_string();

            let filename = path
                .strip_prefix(&self.config.content_dir)
                .unwrap()
                .to_string_lossy();

            info!("{}/{}", hash, filename);

            self.hasharc
                .clone()
                .write()
                .unwrap()
                .insert(filename.to_string(), hash);
        });

        info!("Done calculating file hashes.");
        Ok(())
    }
}
