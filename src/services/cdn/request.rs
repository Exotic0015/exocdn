use crate::CdnAppState;
use axum::extract::{Path, State};
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
    hash: String,
    file: String,
}

pub async fn request(
    Path(RequestStruct { hash, file }): Path<RequestStruct>,
    State(state): State<Arc<CdnAppState>>,
    uri: Uri,
) -> Result<impl IntoResponse, StatusCode> {
    if &hash
        == match match state.hasharc.clone().read() {
            Ok(x) => x,
            Err(err) => {
                warn!("{}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        .get(&file)
        {
            Some(x) => x,
            None => {
                return Err(StatusCode::NOT_FOUND);
            }
        }
    {
        // If the hash matches, attempt to open and serve the requested file
        let path = match current_dir() {
            Ok(x) => x,
            Err(err) => {
                warn!("{}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        .join(&state.content_dir)
        .join(&file);

        // TODO: add etag
        let req = match Request::builder().uri(uri).body(Body::empty()) {
            Ok(x) => x,
            Err(err) => {
                warn!("{}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        return Ok(ServeFile::new(path).oneshot(req).await);
    }

    // If the hash doesn't match, return a "Not Found" response
    Err(StatusCode::NOT_FOUND)
}
