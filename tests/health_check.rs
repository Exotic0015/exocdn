use common::*;

pub mod common;

#[tokio::test]
async fn health_check() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let response = rq_get(&client, &format!("{address}/health_check")).await;
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}
