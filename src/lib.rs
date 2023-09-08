use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::TcpListener;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;

mod calculate_hashes;
mod services;

/// Application state structure, including a hash lock and content directory
pub struct AppState {
    hashlock: Arc<HashMap<String, String>>,
    content_dir: String,
}

/// Function to initialize the application state
pub fn init_state(content_dir: String) -> Result<AppState, Box<dyn Error>> {
    // Create a new empty hashmap to store file hashes
    let mut hashmap = HashMap::new();

    // Calculate file hashes and populate the hashmap
    calculate_hashes::calculate_hashes(&content_dir, &mut hashmap)?;

    // Wrap the hashmap in an Arc for threaded access
    let hashlock = Arc::new(hashmap);

    // Create and return the application state
    Ok(AppState {
        hashlock,
        content_dir: content_dir.clone(),
    })
}

/// Configure the Axum application with routes, middleware, and shared state
fn config_app(content_dir: String) -> Result<Router, Box<dyn Error>> {
    // Initialize the shared application state
    let shared_state = Arc::new(init_state(content_dir)?);
    Ok(Router::new()
        // Define routes and associate them with request handlers
        .route("/request/:hash/*file", get(services::request))
        .route("/health_check", get(services::health_check))
        // Attach the shared state
        .with_state(shared_state)
        // Add middleware
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(
                    tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
                )
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        )
        .layer(CompressionLayer::new()))
}

/// Run without TLS
pub async fn run(
    listener: TcpListener,
    content_dir: String,
) -> Result<impl Future<Output = std::io::Result<()>> + Sized, Box<dyn Error>> {
    // Configure the application
    let app = config_app(content_dir)?;

    // Create and return the server
    Ok(axum_server::from_tcp(listener).serve(app.into_make_service()))
}

/// Run with TLS
pub async fn run_tls(
    listener: TcpListener,
    content_dir: String,
    cert_path: String,
    key_path: String,
) -> Result<impl Future<Output = std::io::Result<()>> + Sized, Box<dyn Error>> {
    // Load TLS configuration from certificate and private key files
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

    // Configure the application
    let app = config_app(content_dir)?;

    // Create and return the server
    Ok(axum_server::from_tcp_rustls(listener, tls_config).serve(app.into_make_service()))
}
