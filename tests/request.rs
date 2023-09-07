use std::fs::File;
use std::io::Read;

mod common;

#[tokio::test]
async fn request_returns_correct_file() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let mut file = File::open("tests/testcontent/testfile.txt").unwrap();
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents).unwrap();

    let hash = blake3::hash(&file_contents).to_string();

    let response = client
        .get(&format!("{}/request/{}/testfile.txt", &address, &hash))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), file_contents);
}

#[tokio::test]
async fn bad_hash_returns_404() {
    let address = common::start_app().await;
    let client = reqwest::Client::new();

    let response = client
        .get(&format!(
            "{}/request/wrong test hash/testfile.txt",
            &address,
        ))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status(), 404);
}
