use crate::DrmAppState;
use axum::extract::{Form, State};
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::services::ServeFile;

#[derive(Deserialize)]
pub struct RequestStruct {
    token: String,
    file: String,
}

pub async fn request_post(
    State(state): State<Arc<DrmAppState>>,
    uri: Uri,
    Form(parameters): Form<RequestStruct>,
) -> Result<impl IntoResponse, StatusCode> {
    if !state.config.tokens.contains(&parameters.token) {
        if state.config.forbidden_file.is_empty() {
            return Err(StatusCode::FORBIDDEN);
        }

        let forbidden_file_path = PathBuf::new()
            .join(&state.config.content_dir)
            .join(&state.config.forbidden_file);

        return Ok((
            StatusCode::FORBIDDEN,
            ServeFile::new(forbidden_file_path)
                .oneshot(crate::Internal::build_req(uri)?)
                .await,
        ));
    }

    let path = PathBuf::new()
        .join(&state.config.content_dir)
        .join(&parameters.file);

    if !state.config.allowed_extensions.contains(
        &match path.extension() {
            Some(x) => x,
            None => return Err(StatusCode::NOT_FOUND),
        }
        .to_string_lossy()
        .to_string(),
    ) {
        return Err(StatusCode::NOT_FOUND);
    }

    if !path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok((
        StatusCode::OK,
        ServeFile::new(path)
            .oneshot(crate::Internal::build_req(uri)?)
            .await,
    ))
}
