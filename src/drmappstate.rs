use std::collections::HashSet;
use std::error::Error;
use tracing::warn;

pub struct DrmAppState {
    pub content_dir: String,
    pub forbidden_file_name: String,
    pub allowed_extensions: HashSet<String>,
    pub tokens: HashSet<String>,
}

impl DrmAppState {
    pub fn new(
        content_dir: String,
        forbidden_file_name: String,
        allowed_extensions: HashSet<String>,
        tokens: HashSet<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let state = Self {
            content_dir,
            forbidden_file_name,
            allowed_extensions,
            tokens,
        };

        state.forbidden_file_check();

        Ok(state)
    }

    fn forbidden_file_check(&self) -> bool {
        if self.forbidden_file_name.is_empty() {
            return true;
        }
        let path = std::path::Path::new(&self.forbidden_file_name);
        let path_exists = path.exists();
        if !path_exists {
            warn!("Forbidden file {} not found!", &self.forbidden_file_name);
        }
        path_exists
    }
}
