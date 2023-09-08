use std::net::TcpListener;

pub async fn start_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();

    let server = exocdn::run(listener, String::from("tests/content"))
        .await
        .unwrap();
    tokio::spawn(server);

    format!("http://127.0.0.1:{}", port)
}
