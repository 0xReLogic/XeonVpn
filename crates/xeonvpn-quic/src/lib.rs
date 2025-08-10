use quinn::{Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};

async fn handle_doh_query(
    query: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // query is expected like: "DOH example.com" (domain only). Optional type not supported yet.
    let domain = query.trim();
    let encoded = urlencoding::encode(domain);
    let url = format!("https://cloudflare-dns.com/dns-query?name={encoded}&type=A");
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    let status_code = status.as_u16();
    let out = format!("{{\"status\":{status_code},\"body\":{body}}}");
    Ok(out.into_bytes())
}

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
        let len = cert_der.len();
        info!("wrote server_cert.der ({len} bytes)");
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
    let local = endpoint.local_addr()?;
    info!("QUIC server listening on {local}");

    while let Some(connecting) = endpoint.accept().await {
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    info!("new connection: {remote}");
                    loop {
                        match connection.accept_bi().await {
                            Ok((mut send, mut recv)) => {
                                match recv.read_to_end(64 * 1024).await {
                                    Ok(data) => {
                                        // Try to interpret as UTF-8 command
                                        if let Ok(text) = std::str::from_utf8(&data) {
                                            let t = text.trim();
                                            if let Some(rest) = t.strip_prefix("DOH ") {
                                                info!("DoH request for domain: {rest}");
                                                match handle_doh_query(rest).await {
                                                    Ok(json_bytes) => {
                                                        if let Err(e) =
                                                            send.write_all(&json_bytes).await
                                                        {
                                                            error!("send DoH resp error: {e}");
                                                        }
                                                    }
                                                    Err(e) => {
                                                        let msg = e.to_string();
                                                        let _ =
                                                            send.write_all(msg.as_bytes()).await;
                                                    }
                                                }
                                                let _ = send.finish().await;
                                            } else {
                                                // Fallback echo
                                                if let Err(e) = send.write_all(&data).await {
                                                    error!("send error: {e}");
                                                }
                                                let _ = send.finish().await;
                                            }
                                        } else {
                                            // Non-UTF8 payload: echo
                                            if let Err(e) = send.write_all(&data).await {
                                                error!("send error: {e}");
                                            }
                                            let _ = send.finish().await;
                                        }
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

    Ok(())
}
