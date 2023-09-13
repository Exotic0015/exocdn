use std::collections::HashMap;

pub mod common;
use common::*;

static URL: &str = "/drm/request";

#[tokio::test]
async fn request_forbids_bad_token() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "bad_token");
    params.insert("file", "");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn request_requires_token_and_file_name() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let response = rq_post(&client, &format!("{address}{URL}")).await;

    assert_eq!(response.status(), 415);

    let mut params = HashMap::new();
    params.insert("token", "");
    params.insert("file", "");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_ne!(response.status(), 415);
}

#[tokio::test]
async fn good_token_returns_correct_file() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "testfile.txt");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert!(response.status().is_success());

    assert_eq!(
        response.bytes().await.unwrap(),
        file_to_byte_vec("tests/cdn_test_content/testfile.txt")
    )
}

#[tokio::test]
async fn nested_files() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "nested/nestedfile.txt");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.unwrap(),
        file_to_byte_vec("tests/cdn_test_content/nested/nestedfile.txt")
    );
}

#[tokio::test]
async fn path_traversal_attack_returns_404() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "../../../../../../etc/passwd");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_eq!(response.status(), 404);
    assert_ne!(
        response.bytes().await.unwrap(),
        file_to_byte_vec("/etc/passwd")
    );
}

#[tokio::test]
async fn good_token_and_bad_file_returns_404() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "non-existing.txt");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn bad_token_returns_forbidden_file() {
    let forbidden_file = file_to_byte_vec("tests/cdn_test_content/forbidden.txt");

    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "bad_token");
    params.insert("file", "non-existing");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_eq!(response.status(), 403);
    assert_eq!(response.bytes().await.unwrap(), forbidden_file);

    params.insert("file", "testfile.txt");

    let response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    assert_eq!(response.status(), 403);
    assert_eq!(response.bytes().await.unwrap(), forbidden_file);
}

#[tokio::test]
async fn dont_cache_files() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "drm-cache-test.txt");

    let file_path = "tests/cdn_test_content/drm-cache-test.txt";

    let original_contents = file_to_byte_vec(file_path);

    let first_response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    tokio::fs::write(&file_path, "not cached!")
        .await
        .expect("Could not write to drm-cache-test.txt!");

    let second_response = rq_post_form(&client, &format!("{address}{URL}"), &params).await;

    tokio::fs::write(&file_path, &original_contents)
        .await
        .expect("Could not write to drm-cache-test.txt!");

    assert_ne!(
        &first_response.bytes().await.unwrap(),
        &second_response.bytes().await.unwrap()
    );
}

#[tokio::test]
async fn concurrent_requests_for_same_file() {
    let address = start_app().await;
    let client = reqwest::Client::new();

    // File to be requested concurrently
    let file_contents = file_to_byte_vec("tests/cdn_test_content/testfile.txt");

    // Number of concurrent requests to simulate
    let num_concurrent_requests = 50;

    // Vector to hold the spawned tasks
    let mut tasks = Vec::new();

    for _ in 0..num_concurrent_requests {
        let address_clone = address.clone();
        let file_contents_clone = file_contents.clone();
        let client_clone = client.clone();

        // Spawn a new task for each concurrent request
        let task = tokio::spawn(async move {
            let mut params = HashMap::new();
            params.insert("token", "test_token1");
            params.insert("file", "testfile.txt");

            let response =
                rq_post_form(&client_clone, &format!("{address_clone}{URL}"), &params).await;

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
