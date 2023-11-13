use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;

use dashmap::DashSet;
use reqwest::{Client, IntoUrl, Response};

pub async fn start_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();

    let allowed_extensions = DashSet::new();
    allowed_extensions.insert(String::from("txt"));
    let tokens = DashSet::new();
    tokens.insert(String::from("test_token1"));

    let config = exocdn::Settings {
        port,
        tls_settings: exocdn::TlsSettings::default(),
        cdn_settings: exocdn::CdnSettings {
            enabled: true,
            content_dir: String::from("tests/cdn_test_content"),
        },
        drm_settings: exocdn::DrmSettings {
            enabled: true,
            content_dir: String::from("tests/cdn_test_content"),
            forbidden_file: String::from("forbidden.txt"),
            allowed_extensions,
            tokens,
        },
    };

    let server = exocdn::run(listener, config).await.unwrap();
    tokio::spawn(server);

    format!("http://127.0.0.1:{}", port)
}

pub async fn rq_get(client: &Client, url: impl IntoUrl + Send) -> Response {
    client
        .get(url)
        .send()
        .await
        .expect("Failed to execute request.")
}

pub async fn rq_post_form(
    client: &Client,
    url: impl IntoUrl + Send,
    params: &HashMap<&str, &str>,
) -> Response {
    client
        .post(url)
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.")
}

pub async fn rq_post(client: &Client, url: impl IntoUrl + Send) -> Response {
    client
        .post(url)
        .send()
        .await
        .expect("Failed to execute request.")
}

pub fn file_to_byte_vec(path: impl AsRef<Path>) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).unwrap();

    file_contents
}
