use quinn::{Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

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

/// Linux-only QUIC server with basic TUN framing handler.
#[cfg(target_os = "linux")]
pub async fn serve_quic_tun(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_config = build_server_config()?;
    let addr: SocketAddr = addr.parse()?;
    let endpoint = Endpoint::server(server_config, addr)?;
    let local = endpoint.local_addr()?;
    info!("QUIC server listening on {local}");

    // Open TUN once and share across tasks. Server IP: 10.123.0.1/24
    let dev = Arc::new(Mutex::new(
        xeonvpn_net::open_tun_named("xeonvpnS0", std::net::Ipv4Addr::new(10, 123, 0, 1))
            .await?,
    ));

    while let Some(connecting) = endpoint.accept().await {
        let dev = dev.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    info!("new connection: {remote}");
                    loop {
                        match connection.accept_bi().await {
                            Ok((mut send, mut recv)) => {
                                // Split into two parallel tasks per stream: uplink and downlink
                                let dev_u = dev.clone();
                                let uplink = tokio::spawn(async move {
                                    loop {
                                        // Read header from QUIC
                                        let mut hdr = [0u8; 8];
                                        if let Err(e) = recv.read_exact(&mut hdr).await {
                                            error!("recv header error: {e}");
                                            break;
                                        }
                                        if &hdr[0..4] != b"TUN " {
                                            error!("bad magic on TUN stream");
                                            break;
                                        }
                                        let len = u32::from_be_bytes([
                                            hdr[4], hdr[5], hdr[6], hdr[7],
                                        ]) as usize;
                                        let mut payload = vec![0u8; len.min(65535)];
                                        if let Err(e) = recv.read_exact(&mut payload).await {
                                            error!("recv payload error: {e}");
                                            break;
                                        }

                                        // Write payload into server TUN (uplink inject)
                                        let mut guard = dev_u.lock().await;
                                        if let Err(e) = guard.write_all(&payload).await {
                                            error!("tun write error: {e}");
                                            break;
                                        }
                                    }
                                });

                                let dev_d = dev.clone();
                                let downlink = tokio::spawn(async move {
                                    loop {
                                        // Read packet from TUN and forward to client
                                        let mut buf = vec![0u8; 2000];
                                        let n = {
                                            let mut guard = dev_d.lock().await;
                                            match guard.read(&mut buf).await {
                                                Ok(n) => n,
                                                Err(e) => {
                                                    error!("tun read error: {e}");
                                                    0
                                                }
                                            }
                                        };
                                        if n == 0 {
                                            continue;
                                        }
                                        buf.truncate(n);

                                        let mut out = Vec::with_capacity(8 + buf.len());
                                        out.extend_from_slice(b"TUN ");
                                        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
                                        out.extend_from_slice(&buf);

                                        if let Err(e) = send.write_all(&out).await {
                                            error!("send error: {e}");
                                            break;
                                        }
                                    }
                                });

                                let _ = tokio::join!(uplink, downlink);
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
