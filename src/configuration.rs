use axum::BoxError;
use dashmap::DashSet;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[allow(unused)]
pub struct CdnSettings {
    pub enabled: bool,
    pub content_dir: String,
}

#[derive(Deserialize, Debug)]
#[allow(unused)]
pub struct DrmSettings {
    pub enabled: bool,
    pub content_dir: String,
    pub forbidden_file: String,
    pub allowed_extensions: DashSet<String>,
    pub tokens: DashSet<String>,
}

#[derive(Deserialize, Debug, Default)]
#[allow(unused)]
pub struct TlsSettings {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Deserialize, Debug)]
#[allow(unused)]
pub struct Settings {
    pub port: u16,
    pub tls_settings: TlsSettings,
    pub cdn_settings: CdnSettings,
    pub drm_settings: DrmSettings,
}

impl Settings {
    /// Load the configuration from a file
    pub fn from_file(name: &str) -> Result<Self, BoxError> {
        let config_str = std::fs::read_to_string(name)?;
        Ok(toml::from_str(&config_str)?)
    }
}
