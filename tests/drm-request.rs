use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

mod common;

static URL: &str = "/drm/request";

#[tokio::test]
async fn request_forbids_bad_token() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "bad_token");
    params.insert("file", "");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn request_requires_token_and_file_name() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let response = client
        .post(&format!("{address}{URL}"))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 415);

    let mut params = HashMap::new();
    params.insert("token", "");
    params.insert("file", "");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_ne!(response.status(), 415);
}

#[tokio::test]
async fn good_token_returns_correct_file() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "testfile.txt");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(response.status().is_success());

    let mut test_file = String::new();
    let mut f = File::open("tests/cdn_test_content/testfile.txt").expect("Could not open file!");
    f.read_to_string(&mut test_file)
        .expect("Could not read file to string!");
    assert_eq!(
        response
            .text()
            .await
            .expect("Could not read response text!"),
        test_file
    )
}

#[tokio::test]
async fn nested_files() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut file = File::open("tests/cdn_test_content/nested/nestedfile.txt").unwrap();
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).unwrap();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "nested/nestedfile.txt");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), file_contents);
}

#[tokio::test]
async fn path_traversal_attack_returns_404() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "../../../../../../etc/passwd");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn good_token_and_bad_file_returns_404() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "non-existing.txt");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn bad_token_returns_forbidden_file() {
    let mut test_file = String::new();
    let mut f = File::open("tests/cdn_test_content/forbidden.txt").expect("Could not open file!");
    f.read_to_string(&mut test_file)
        .expect("Could not read file to string!");

    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "bad_token");
    params.insert("file", "non-existing");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 403);
    assert_eq!(
        response
            .text()
            .await
            .expect("Could not read response text!"),
        test_file
    );

    params.insert("file", "testfile.txt");

    let response = client
        .post(&format!("{address}{URL}"))
        .form(&params)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 403);
    assert_eq!(
        response
            .text()
            .await
            .expect("Could not read response text!"),
        test_file
    );
}

#[tokio::test]
async fn dont_cache_files() {
    async fn make_request(
        client: &reqwest::Client,
        address: &str,
        params: &HashMap<&str, &str>,
    ) -> String {
        client
            .post(&format!("{address}{URL}"))
            .form(params)
            .send()
            .await
            .expect("Failed to execute request.")
            .text()
            .await
            .expect("Failed to read response!")
    }

    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("token", "test_token1");
    params.insert("file", "drm-cache-test.txt");

    let file_path = "tests/cdn_test_content/drm-cache-test.txt";

    let original_contents = tokio::fs::read_to_string(&file_path)
        .await
        .expect("Failed to read drm-cache-test.txt!");

    let first_response = make_request(&client, &address, &params).await;

    tokio::fs::write(&file_path, "not cached!")
        .await
        .expect("Could not write to drm-cache-test.txt!");

    let second_response = make_request(&client, &address, &params).await;

    tokio::fs::write(&file_path, &original_contents)
        .await
        .expect("Could not write to drm-cache-test.txt!");

    assert_ne!(&first_response, &second_response);
}

#[tokio::test]
async fn concurrent_requests_for_same_file() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    // File to be requested concurrently
    let mut file = File::open("tests/cdn_test_content/testfile.txt").unwrap();
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).unwrap();

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

            let response = client_clone
                .post(&format!("{address_clone}{URL}"))
                .form(&params)
                .send()
                .await
                .expect("Failed to execute request.");

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
