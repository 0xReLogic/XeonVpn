use std::{fs, sync::Arc};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

fn build_client_config(
    cert_der: &[u8],
) -> Result<quinn::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
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
        fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init()
    };
    let banner = xeonvpn_core::banner("Client");
    info!("{banner}");

    // Optional: Linux TUN POC mode
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tun") {
        #[cfg(target_os = "linux")]
        {
            xeonvpn_net::run_tun_poc().await?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("--tun is only supported on Linux for now");
            return Ok(());
        }
    }

    // Handle DoH POC: `--doh <domain>`
    if let Some(i) = args.iter().position(|a| a == "--doh") {
        let domain = args.get(i + 1).map(String::as_str).unwrap_or("example.com");
        // Load server cert
        let cert_der = fs::read("server_cert.der").or_else(|_| fs::read("../server_cert.der"))?;
        let client_config = build_client_config(&cert_der)?;

        // Create endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        // Connect
        let connect = endpoint.connect("127.0.0.1:4433".parse()?, "localhost")?;
        let connection = connect.await?;
        let addr = connection.remote_address();
        info!("connected: {addr}");
        println!("[client] connected to {addr}");

        // Send DoH command
        let (mut send, mut recv) = connection.open_bi().await?;
        let cmd = format!("DOH {domain}");
        send.write_all(cmd.as_bytes()).await?;
        send.finish().await?;

        let buf = recv.read_to_end(256 * 1024).await?; // allow larger JSON
        let resp = String::from_utf8_lossy(&buf);
        println!("[client] DoH response: {resp}");
        return Ok(());
    }

    // Load server cert
    let cert_der = fs::read("server_cert.der").or_else(|_| fs::read("../server_cert.der"))?;
    let client_config = build_client_config(&cert_der)?;

    // Create endpoint
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connect = endpoint.connect("127.0.0.1:4433".parse()?, "localhost")?;
    let connection = connect.await?;
    let addr = connection.remote_address();
    info!("connected: {addr}");
    println!("[client] connected to {addr}");

    // Open a bidi stream and perform echo
    let (mut send, mut recv) = connection.open_bi().await?;
    let msg = b"hello from client";
    send.write_all(msg).await?;
    send.finish().await?;

    let buf = recv.read_to_end(64 * 1024).await?;
    let echoed = String::from_utf8_lossy(&buf);
    info!("echoed back: {echoed}");
    println!("[client] echoed back: {echoed}");

    Ok(())
}
