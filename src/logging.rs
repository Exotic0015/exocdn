use axum::http::Request;
use tower_http::LatencyUnit;
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::{DefaultOnResponse, MakeSpan, TraceLayer};
use tracing::{Level, Span, span};

#[derive(Clone)]
pub struct DrmMakeSpan;
impl<B> MakeSpan<B> for DrmMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let headers = request.headers();
        span!(
            Level::INFO,
            "DRM",
            version = ?request.version(),
            method = ?request.method(),
            //uri = %request.uri(), // useless since uri is always /request
            //headers = ?request.headers(), // only for debugging, cherrypick the ones we actually need
            user_agent = ?headers.get("user-agent"),
            x_forwarded_for = ?headers.get("x-forwarded-for"),
            x_real_ip = ?headers.get("x-real-ip"),
        )
    }
}

#[derive(Clone)]
pub struct CdnMakeSpan;
impl<B> MakeSpan<B> for CdnMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let headers = request.headers();
        span!(
            Level::INFO,
            "CDN",
            version = ?request.version(),
            method = ?request.method(),
            uri = %request.uri(),
            //headers = ?request.headers(), // only for debugging, cherrypick the ones we actually need
            user_agent = ?headers.get("user-agent"),
            x_forwarded_for = ?headers.get("x-forwarded-for"),
            x_real_ip = ?headers.get("x-real-ip"),
        )
    }
}

pub fn new_log_layer() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>> {
    TraceLayer::new_for_http().on_response(
        DefaultOnResponse::new()
            .level(Level::INFO)
            .latency_unit(LatencyUnit::Micros),
    )
}
