use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;
use tower::ServiceExt;
use tower_http::services::ServeFile;
use tracing::info;

use crate::{DrmAppState, Internal};

#[derive(Deserialize)]
pub struct RequestStruct {
    token: String,
    file: String,
}

pub async fn request_post(
    State(state): State<Arc<DrmAppState>>,
    uri: Uri,
    Form(query): Form<RequestStruct>,
) -> Result<impl IntoResponse, StatusCode> {
    info!(
        "incoming request for {:?} with token {:?}",
        query.file, query.token
    );

    // If the token is incorrect, return 403 together with the forbidden file (if enabled)
    if !state.config.tokens.contains(&query.token) {
        if state.config.forbidden_file.is_empty() {
            return Err(StatusCode::FORBIDDEN);
        }

        let mut path = PathBuf::new();
        path.push(&state.config.content_dir);
        path.push(&state.config.forbidden_file);

        return Ok((
            StatusCode::FORBIDDEN,
            ServeFile::new(path)
                .oneshot(Internal::build_req(uri)?)
                .await,
        ));
    }

    let mut path = PathBuf::new();
    path.push(&state.config.content_dir);
    path.push(&query.file);

    // Check if the file extension is on the whitelist
    if !state.config.allowed_extensions.contains(
        &*match path.extension() {
            Some(x) => x,
            None => return Err(StatusCode::NOT_FOUND),
        }
        .to_string_lossy(),
    ) {
        return Err(StatusCode::NOT_FOUND);
    }

    // If the file exists, return it with 200
    // We have to do it this way because we return the result as a tuple in order
    // to change the status code from tower's ServeFile default 200 to 403 in the
    // case of incorrect token
    Ok((
        if path.exists() {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        },
        ServeFile::new(path)
            .oneshot(Internal::build_req(uri)?)
            .await,
    ))
}
