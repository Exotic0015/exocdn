use config::Config;

#[derive(serde::Deserialize)]
pub struct Settings {
    pub port: u16,
    pub cert_path: String,
    pub key_path: String,
    pub content_dir: String,
}

pub fn get_config() -> Result<Settings, config::ConfigError> {
    let settings = Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;

    settings.try_deserialize()
}
