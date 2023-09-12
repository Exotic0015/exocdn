use std::collections::HashMap;
use std::net::TcpListener;

pub async fn start_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();

    let config = exocdn::Settings {
        port,
        tls_settings: exocdn::TlsSettings {
            cert_path: "".to_string(),
            key_path: "".to_string(),
        },
        cdn_settings: exocdn::CdnSettings {
            enabled: true,
            content_dir: "tests/cdn_test_content".to_string(),
        },
        drm_settings: exocdn::DrmSettings {
            enabled: true,
            content_dir: "tests/cdn_test_content".to_string(),
            forbidden_file: "forbidden.txt".to_string(),
            tokens: HashMap::from([("test_token1".to_string(), true)]),
        },
    };

    let server = exocdn::run(listener, config).await.unwrap();
    tokio::spawn(server);

    format!("http://127.0.0.1:{}", port)
}
