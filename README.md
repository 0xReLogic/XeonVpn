# XeonVPN

An advanced Rust‑based VPN targeting Asia regions (SG, JP, ID, HK, IN). Focused on performance, privacy, and anti‑censorship/obfuscation.

This repo currently ships a Linux TUN‑over‑QUIC POC: a QUIC server and client that maintain persistent TUN devices and a single long‑lived bidirectional QUIC stream for full‑duplex packet forwarding.

## Status
- QUIC server with TLS 1.3 (self‑signed), writes `server_cert.der` for local testing.
- Client Linux TUN mode with persistent interface and full‑duplex tunnel over one QUIC bidi stream.
- End‑to‑end ICMP works: client can ping server TUN IP and receive replies over the tunnel.
- DoH POC still available on a separate command.

## Repository Structure
- `apps/server/`: QUIC server application (TUN handler for Linux POC).
- `apps/client/`: QUIC client application (echo, DoH, Linux TUN loop modes).
- `crates/xeonvpn-core/`: common utilities, versioning, banner.
- `crates/xeonvpn-net/`: TUN management and networking helpers.
- `crates/xeonvpn-quic/`: QUIC transport, TLS config, server handlers.
- `todo.md`: internal roadmap (git‑ignored by design).

## Getting Started
### Prerequisites
- Rust (stable): https://www.rust-lang.org/
- Linux (WSL2 tested). TUN requires root privileges (sudo).
- Windows support is planned (Wintun), not included in this POC.

### Build
```bash
cargo build
```

### Run: QUIC Server with TUN (Linux/WSL2)
Generates `server_cert.der` in repo root for client trust.
```bash
sudo -E env "PATH=/mnt/d/.cargo/bin:$PATH" RUST_LOG=info cargo run -p xeonvpn-server -- --tun-server
# verify
ip addr show dev xeonvpnS0   # expect 10.123.0.1/24
```

### Run: QUIC Client with TUN Loop (Linux/WSL2)
Uses a single long‑lived bidi stream to forward packets both ways.
```bash
sudo -E env "PATH=/mnt/d/.cargo/bin:$PATH" RUST_LOG=info cargo run -p xeonvpn-client -- --tun-loop
# verify
ip addr show dev xeonvpn0    # expect 10.123.0.2/24
```

### Test: ICMP over Tunnel
```bash
ping -c 3 10.123.0.1
```
You should see 0% packet loss if the tunnel is up.

### Note on TCP Testing on the Same Host
When client and server run on the same machine, routes to `10.123.0.1` may resolve to `lo` (loopback), so tools like `nc` might not traverse the TUN devices. For an end‑to‑end TCP test over TUN, run server in a separate VM/container/netns or connect the client to a non‑loopback server address.

### DoH POC
```bash
cargo run -p xeonvpn-server
cargo run -p xeonvpn-client -- --doh example.com
```
The client connects to the QUIC server and prints the JSON response from Cloudflare DoH.

## Roadmap
Highlights:
- QUIC data‑plane improvements (framing v0, auth PSK, keepalive/reconnect).
- Windows client with Wintun.
- Obfuscation/anti‑censorship, multi‑region (Asia‑first), packaging & UX.

## Development Notes
- Logging uses `tracing` (INFO by default). Server writes `server_cert.der` for local trust.
- QUIC via `quinn` and TLS 1.3 via `rustls`; self‑signed certificates generated with `rcgen` for development only.

## Security
This is a POC under active development. Do not use in production. Certificates/keys generated here are for local testing only.

## License
TBD.

## Acknowledgements
- `quinn` for QUIC
- `rustls` for TLS 1.3
- `rcgen` for certificate generation
