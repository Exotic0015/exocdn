use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::header::{ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH};
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
    headers: HeaderMap,
    uri: Uri,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if the requested hash matches the requested file
    if let Some(x) = state.hasharc.clone().get(&file) {
        // If the hash matches, attempt to open and serve the requested file
        if hash == *x {
            // HTTP spec requires ETags to be wrapped in double quotes
            let etag_val = format!("\"{}\"", hash);

            // Check if the client's cached ETag matches the current file hash
            if let Some(if_none_match) = headers.get(IF_NONE_MATCH)
                && if_none_match.to_str().unwrap_or("") == etag_val
            {
                // Client already has the file, return 304 Not Modified
                let mut res = StatusCode::NOT_MODIFIED.into_response();
                if let Ok(etag_header) = HeaderValue::from_str(&etag_val) {
                    res.headers_mut().insert(ETAG, etag_header);
                }
                return Ok(res);
            }

            let mut path = PathBuf::new();
            path.push(&state.config.content_dir);
            path.push(&file);

            let mut response = ServeFile::new(path)
                .oneshot(Internal::build_req(uri)?)
                .await
                .into_response();

            if let Ok(etag_header) = HeaderValue::from_str(&etag_val) {
                response.headers_mut().insert(ETAG, etag_header);
            }

            return Ok(response);
        }
    }
    // If the hash doesn't match, return a "Not Found" response
    Err(StatusCode::NOT_FOUND)
}
