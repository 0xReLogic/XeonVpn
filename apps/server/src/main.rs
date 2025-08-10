use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = if std::env::var("RUST_LOG").is_err() {
        fmt().with_env_filter(EnvFilter::default().add_directive("info".parse().unwrap())).try_init()
    } else {
        fmt().with_env_filter(EnvFilter::from_default_env()).try_init()
    };
    info!("{}", xeonvpn_core::banner("Server"));

    let addr = "0.0.0.0:4433";
    info!("starting QUIC server on {addr}");

    let server_task = tokio::spawn(async move {
        if let Err(e) = xeonvpn_quic::serve_quic(addr).await {
            eprintln!("server error: {e}");
        }
    });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received, exiting");

    // Stop background task
    server_task.abort();

    Ok(())
}
