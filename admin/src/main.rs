use admin::{build_router, AppState};
use common::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env();
    let db = common::firestore::connect(&config)
        .await
        .expect("failed to connect to Firestore");
    let port = config.port;
    let state = AppState {
        db,
        rp_origin: config.rp_origin,
        authorization_url: config.authorization_url,
        http: reqwest::Client::new(),
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    tracing::info!("admin service listening on :{port}");
    axum::serve(listener, build_router(state))
        .await
        .expect("server error");
}
