use crate::DrmAppState;
use axum::extract::{Form, State};
use axum::http::{Request, StatusCode, Uri};
use axum::response::IntoResponse;
use hyper::Body;
use serde::Deserialize;
use std::env::current_dir;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::services::ServeFile;
use tracing::warn;

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
    let req = match Request::builder().uri(uri).body(Body::empty()) {
        Ok(x) => x,
        Err(err) => {
            warn!("{}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !state.tokens.contains_key(&parameters.token) {
        if state.forbidden_file_name.is_empty() {
            return Err(StatusCode::FORBIDDEN);
        }

        let path = match current_dir() {
            Ok(x) => x,
            Err(err) => {
                warn!("{}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        .join(&state.content_dir)
        .join(&state.forbidden_file_name);

        return Ok((
            StatusCode::FORBIDDEN,
            ServeFile::new(path).oneshot(req).await,
        ));
    }

    let path = match current_dir() {
        Ok(x) => x,
        Err(err) => {
            warn!("{}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    .join(&state.content_dir)
    .join(&parameters.file);

    if !path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok((StatusCode::OK, ServeFile::new(path).oneshot(req).await))
}
