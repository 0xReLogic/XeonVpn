use std::{net::SocketAddr, sync::Arc};
use quinn::{Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use tracing::{error, info};

fn build_server_config() -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert = generate_simple_self_signed(["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![rustls::Certificate(cert_der.clone())];
    let priv_key = rustls::PrivateKey(key_der);

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;

    server_crypto.alpn_protocols = vec![b"hq-29".to_vec(), b"h3".to_vec()];

    // Write server certificate to disk for client trust during local testing
    if let Err(e) = std::fs::write("server_cert.der", &cert_der) {
        error!("failed to write server_cert.der: {e}");
    } else {
        info!("wrote server_cert.der ({} bytes)", cert_der.len());
    }

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_concurrent_bidi_streams(100u32.into());
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

pub async fn serve_quic(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_config = build_server_config()?;
    let addr: SocketAddr = addr.parse()?;
    let endpoint = Endpoint::server(server_config, addr)?;
    info!("QUIC server listening on {}", endpoint.local_addr()?);

    loop {
        match endpoint.accept().await {
            Some(connecting) => {
                tokio::spawn(async move {
                    match connecting.await {
                        Ok(connection) => {
                            info!("new connection: {}", connection.remote_address());
                            loop {
                                match connection.accept_bi().await {
                                    Ok((mut send, mut recv)) => {
                                        match recv.read_to_end(64 * 1024).await {
                                            Ok(data) => {
                                                if let Err(e) = send.write_all(&data).await { error!("send error: {e}"); }
                                                let _ = send.finish().await;
                                            }
                                            Err(e) => {
                                                error!("recv error: {e}");
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("accept_bi error: {e}");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => error!("handshake failed: {e}"),
                    }
                });
            }
            None => {
                // Endpoint closed
                break;
            }
        }
    }

    Ok(())
}
