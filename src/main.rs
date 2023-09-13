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

static LOG_FILENAME: &str = "exocdn.log";
static CONFIG_FILENAME: &str = "config.toml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let log_file = Path::new(LOG_FILENAME);
    if log_file.exists() {
        std::fs::remove_file(log_file)?;
    }

    let appender = rolling::never("", LOG_FILENAME);
    let (non_blocking_appender, _guard) = non_blocking(appender);

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
                .with_writer(io::stdout)
                .with_filter(LevelFilter::WARN),
        )
        .init();

    let config = match exocdn::Settings::from_file(CONFIG_FILENAME) {
        Ok(x) => x,
        Err(e) => {
            error!("Config: {}", e);
            std::process::exit(1);
        }
    };

    let address = format!("0.0.0.0:{}", config.port);
    let listener =
        TcpListener::bind(address).expect(&format!("Failed to bind port {}", config.port));

    if config.tls_settings.key_path.is_empty() || config.tls_settings.cert_path.is_empty() {
        warn!("Running an insecure (no TLS) instance!");

        // Run the server without TLS
        run(listener, config).await?.await?;
    } else {
        // Run the server with TLS
        run_tls(listener, config).await?.await?;
    }

    Ok(())
}
