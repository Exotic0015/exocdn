pub mod common;
use common::*;

static URL: &str = "/cdn/request";

#[tokio::test]
async fn request_returns_correct_file() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let file_contents = file_to_byte_vec("tests/cdn_test_content/testfile.txt");

    let hash = blake3::hash(&file_contents).to_string();
    let response = rq_get(&client, &format!("{address}{URL}/{hash}/testfile.txt")).await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), file_contents);
}

#[tokio::test]
async fn nested_files() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let file_contents = file_to_byte_vec("tests/cdn_test_content/nested/nestedfile.txt");

    let hash = blake3::hash(&file_contents).to_string();
    let response = rq_get(
        &client,
        &format!("{address}{URL}/{hash}/nested/nestedfile.txt"),
    )
    .await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), file_contents);
}

#[tokio::test]
async fn bad_hash_returns_404() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let response = rq_get(
        &client,
        &format!("{address}{URL}/wrong test hash/testfile.txt"),
    )
    .await;

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn bad_file_returns_404() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let response = rq_get(
        &client,
        &format!("{address}{URL}/wrong test hash/non existing file.txt"),
    )
    .await;

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn empty_file() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let hash = blake3::hash(&file_to_byte_vec("tests/cdn_test_content/empty.txt")).to_string();
    let response = rq_get(&client, &format!("{address}{URL}/{hash}/empty.txt")).await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().len(), 0);
}

#[tokio::test]
async fn concurrent_requests_for_same_file() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    // File to be requested concurrently
    let file_contents = file_to_byte_vec("tests/cdn_test_content/testfile.txt");
    let hash = blake3::hash(&file_contents).to_string();

    // Number of concurrent requests to simulate
    let num_concurrent_requests = 50;

    // Vector to hold the spawned tasks
    let mut tasks = Vec::new();

    for _ in 0..num_concurrent_requests {
        let address_clone = address.clone();
        let hash_clone = hash.clone();
        let file_contents_clone = file_contents.clone();
        let client_clone = client.clone();

        // Spawn a new task for each concurrent request
        let task = tokio::spawn(async move {
            let response = rq_get(
                &client_clone,
                &format!("{address_clone}{URL}/{hash_clone}/testfile.txt"),
            )
            .await;

            assert_eq!(response.status(), 200);
            assert_eq!(response.bytes().await.unwrap(), &file_contents_clone);
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    for task in tasks {
        task.await.expect("Task failed.");
    }
}

#[tokio::test]
async fn path_traversal_attack_returns_404() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let file_contents = file_to_byte_vec("/etc/passwd");

    let hash = blake3::hash(&file_contents).to_string();

    let response = rq_get(
        &client,
        &format!("{address}{URL}{hash}/../../../../../../etc/passwd"),
    )
    .await;

    assert_eq!(response.status(), 404);
    assert_ne!(response.bytes().await.unwrap(), file_contents);
}
