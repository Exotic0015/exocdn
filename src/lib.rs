use std::future::Future;
use std::net::TcpListener;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{BoxError, Router};
use axum_server::tls_rustls::RustlsConfig;
use tracing::warn;

#[cfg(feature = "compression")]
use tower_http::compression::CompressionLayer;

use cdnappstate::*;
pub use configuration::*;
use drmappstate::*;

mod services;

mod cdnappstate;
mod configuration;
mod drmappstate;
mod logging;

struct Internal;
impl Internal {
    /// Build a Request from Uri, used when serving files with tower `ServeFile` middleware
    fn build_req(
        uri: axum::http::Uri,
    ) -> Result<axum::http::Request<axum::body::Body>, StatusCode> {
        match axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
        {
            Ok(x) => Ok(x),
            Err(err) => {
                warn!("{}", err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

/// Configure the application with routes, middleware, and shared state
async fn config_app(config: Settings) -> Result<Router, BoxError> {
    let mut app = Router::new().route("/health_check", get(services::health_check));

    if config.cdn_settings.enabled {
        let app_cdn_state = Arc::new(CdnAppState::new(config.cdn_settings).await?);

        let cdn_router = Router::new()
            .route("/request/{hash}/{*file}", get(services::cdn::request))
            .with_state(app_cdn_state)
            .layer(logging::new_log_layer().make_span_with(logging::CdnMakeSpan));

        #[cfg(feature = "compression")]
        let cdn_router = cdn_router.layer(CompressionLayer::new());

        app = app.nest("/cdn", cdn_router);
    }

    if config.drm_settings.enabled {
        let app_drm_state = Arc::new(DrmAppState::new(config.drm_settings)?);

        let drm_router = Router::new()
            .route("/request", post(services::drm::request_post))
            .with_state(app_drm_state)
            .layer(logging::new_log_layer().make_span_with(logging::DrmMakeSpan));

        #[cfg(feature = "compression")]
        let drm_router = drm_router.layer(CompressionLayer::new());

        app = app.nest("/drm", drm_router);
    }

    Ok(app)
}

/// Run without TLS
pub async fn run(
    listener: TcpListener,
    config: Settings,
) -> Result<impl Future<Output = impl Send>, BoxError> {
    // Configure the application
    let app = config_app(config).await?;

    // Create and return the server
    Ok(axum_server::from_tcp(listener).serve(app.into_make_service()))
}

/// Run with TLS
pub async fn run_tls(
    listener: TcpListener,
    config: Settings,
) -> Result<impl Future<Output = impl Send>, BoxError> {
    // Load TLS configuration from certificate and private key files
    let tls_config = RustlsConfig::from_pem_file(
        &config.tls_settings.cert_path,
        &config.tls_settings.key_path,
    )
    .await?;

    // Configure the application
    let app = config_app(config).await?;

    // Create and return the server
    Ok(axum_server::from_tcp_rustls(listener, tls_config).serve(app.into_make_service()))
}
