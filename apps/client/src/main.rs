use std::{fs, sync::Arc};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

fn build_client_config(cert_der: &[u8]) -> Result<quinn::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&rustls::Certificate(cert_der.to_vec()))?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    crypto.alpn_protocols = vec![b"hq-29".to_vec(), b"h3".to_vec()];

    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = if std::env::var("RUST_LOG").is_err() {
        fmt().with_env_filter(EnvFilter::new("info")).try_init()
    } else {
        fmt().with_env_filter(EnvFilter::from_default_env()).try_init()
    };
    info!("{}", xeonvpn_core::banner("Client"));

    // Load server cert
    let cert_der = fs::read("server_cert.der").or_else(|_| fs::read("../server_cert.der"))?;
    let client_config = build_client_config(&cert_der)?;

    // Create endpoint
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connect = endpoint.connect("127.0.0.1:4433".parse()?, "localhost")?;
    let connection = connect.await?;
    info!("connected: {}", connection.remote_address());
    println!("[client] connected to {}", connection.remote_address());

    // Open a bidi stream and perform echo
    let (mut send, mut recv) = connection.open_bi().await?;
    let msg = b"hello from client";
    send.write_all(msg).await?;
    send.finish().await?;

    let buf = recv.read_to_end(64 * 1024).await?;
    info!("echoed back: {}", String::from_utf8_lossy(&buf));
    println!("[client] echoed back: {}", String::from_utf8_lossy(&buf));

    Ok(())
}
