use std::collections::HashMap;
use std::error::Error;
use tracing::warn;

pub struct DrmAppState {
    pub content_dir: String,
    pub forbidden_file_name: String,
    pub tokens: HashMap<String, bool>,
}

impl DrmAppState {
    pub fn new(
        content_dir: String,
        forbidden_file_name: String,
        tokens: HashMap<String, bool>,
    ) -> Result<Self, Box<dyn Error>> {
        let state = Self {
            content_dir,
            forbidden_file_name,
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
