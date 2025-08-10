//! Linux TUN POC
//! Create a TUN interface `xeonvpn0`, bring it up, and read a single packet.

#![cfg(target_os = "linux")]

use std::{error::Error, net::Ipv4Addr};
use tokio::io::AsyncReadExt;
use tracing::info;

/// Read a single packet from a Linux TUN `xeonvpn0` and return the bytes (truncated to length).
pub async fn read_one_packet() -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    info!("starting Linux TUN POC (xeonvpn0)");

    let mut config = tun::Configuration::default();
    config
        .name("xeonvpn0")
        .address(Ipv4Addr::new(10, 123, 0, 2))
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .mtu(1500)
        .up();

    // Requires `tun` crate with `async` feature
    let mut dev = tun::create_as_async(&config)?;

    let mut buf = vec![0u8; 2000];
    let n = dev.read(&mut buf).await?;
    info!("received {n} bytes from TUN xeonvpn0");
    buf.truncate(n);
    Ok(buf)
}

/// Backward-compatible POC: read one packet and only log the size.
pub async fn run_tun_poc() -> Result<(), Box<dyn Error + Send + Sync>> {
    let pkt = read_one_packet().await?;
    info!("TUN POC read {} bytes", pkt.len());
    Ok(())
}
