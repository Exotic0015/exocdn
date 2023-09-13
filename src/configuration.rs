use config::Config;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
#[allow(unused)]
pub struct CdnSettings {
    pub enabled: bool,
    pub content_dir: String,
}

#[derive(Deserialize)]
#[allow(unused)]
pub struct DrmSettings {
    pub enabled: bool,
    pub content_dir: String,
    pub forbidden_file: String,
    pub allowed_extensions: HashSet<String>,
    pub tokens: HashSet<String>,
}

#[derive(Deserialize)]
#[allow(unused)]
pub struct TlsSettings {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub port: u16,
    pub tls_settings: TlsSettings,
    pub cdn_settings: CdnSettings,
    pub drm_settings: DrmSettings,
}

impl Settings {
    pub fn from_file(name: String) -> Result<Self, config::ConfigError> {
        let settings = Config::builder()
            .add_source(config::File::with_name(&name))
            .build()?;

        settings.try_deserialize()
    }
}
