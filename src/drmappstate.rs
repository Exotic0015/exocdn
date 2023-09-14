use crate::DrmSettings;
use std::error::Error;
use std::path::Path;
use tracing::warn;

pub struct DrmAppState {
    pub config: DrmSettings,
}

impl DrmAppState {
    pub fn new(config: DrmSettings) -> Result<Self, Box<dyn Error>> {
        let state = Self { config };

        state.forbidden_file_check();

        Ok(state)
    }

    /// Warn if forbidden file is enabled but does not exist in the filesystem
    fn forbidden_file_check(&self) -> bool {
        if self.config.forbidden_file.is_empty() {
            return true;
        }
        let path_exists = Path::new(&self.config.forbidden_file).exists();
        if !path_exists {
            warn!("Forbidden file {} not found!", &self.config.forbidden_file);
        }
        path_exists
    }
}
