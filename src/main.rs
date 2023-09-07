mod configuration;

use exocdn::{run, run_tls};
use std::error::Error;
use std::io;
use std::net::TcpListener;
use std::path::Path;
use tracing::level_filters::LevelFilter;
use tracing::{error, warn};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let log_file = Path::new("exocdn.log");
    if log_file.exists() {
        std::fs::remove_file(log_file)?;
    }

    let appender = rolling::never("", "exocdn.log");
    let (non_blocking_appender, _guard) = non_blocking(appender);

    let file_format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(false)
        .with_thread_ids(false)
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
                .with_writer(io::stdout)
                .with_filter(LevelFilter::WARN),
        )
        .init();

    let config = match configuration::get_config() {
        Ok(x) => x,
        Err(e) => {
            error!("Config: {}", e);
            std::process::exit(1);
        }
    };

    let address = format!("0.0.0.0:{}", config.port);
    let listener =
        TcpListener::bind(address).expect(&format!("Failed to bind port {}", config.port));

    if config.key_path.is_empty() || config.cert_path.is_empty() {
        warn!("Running an insecure (no TLS) instance!");

        // Run the server without TLS
        run(listener, config.content_dir).await?.await?;
    } else {
        // Run the server with TLS
        run_tls(
            listener,
            config.content_dir,
            config.cert_path,
            config.key_path,
        )
        .await?
        .await?;
    }

    Ok(())
}
