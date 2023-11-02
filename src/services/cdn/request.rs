use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::CdnAppState;
use crate::Internal;

#[derive(Deserialize)]
pub struct RequestStruct {
    hash: String,
    file: String,
}

pub async fn request(
    Path(RequestStruct { hash, file }): Path<RequestStruct>,
    State(state): State<Arc<CdnAppState>>,
    uri: Uri,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if the requested hash matches the requested file
    if let Some(x) = state.hasharc.clone().get(&file) {
        // If the hash matches, attempt to open and serve the requested file
        if hash == *x {
            let mut path = PathBuf::new();
            path.push(&state.config.content_dir);
            path.push(&file);

            return Ok(ServeFile::new(path)
                .oneshot(Internal::build_req(uri)?)
                .await);
        }
    }
    // If the hash doesn't match, return a "Not Found" response
    Err(StatusCode::NOT_FOUND)
}
