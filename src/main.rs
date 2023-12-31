use std::net::{SocketAddr, TcpListener};
use std::path::Path;

use axum::BoxError;
use tracing::level_filters::LevelFilter;
use tracing::warn;
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use exocdn::{run, run_tls};

#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

static LOG_FILENAME: &str = "exocdn.log";
static CONFIG_FILENAME: &str = "config.toml";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Truncate the log file
    let log_file = Path::new(LOG_FILENAME);
    if log_file.exists() {
        std::fs::remove_file(log_file)?;
    }

    let appender = rolling::never("", LOG_FILENAME);
    let (non_blocking_appender, _guard) = non_blocking(appender);

    // Define the logging format used in the log file
    let file_format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(false)
        .with_thread_ids(true)
        .with_thread_names(false)
        .with_ansi(false)
        .compact();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .event_format(file_format)
                .with_writer(non_blocking_appender)
                .with_filter(LevelFilter::INFO),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(LevelFilter::WARN),
        )
        .init();

    // Load the config from file
    let config = exocdn::Settings::from_file(CONFIG_FILENAME).unwrap_or_else(|e| {
        tracing::error!("Config: {}", e);
        panic!();
    });

    // Create the listener with port defined in config
    let listener =
        TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], config.port))).unwrap_or_else(|_| {
            tracing::error!("Failed to bind to port {}", config.port);
            panic!();
        });

    if config.tls_settings.key_path.is_empty() || config.tls_settings.cert_path.is_empty() {
        // Run the server without TLS
        warn!("Running an insecure (no TLS) instance!");
        run(listener, config).await?.await;
    } else {
        // Run the server with TLS
        run_tls(listener, config).await?.await;
    }

    Ok(())
}
