pub fn init_networking() {
    // Placeholder: in the future, setup TUN/TAP, routing, DNS.
}

#[cfg(target_os = "linux")]
pub mod tun;

#[cfg(target_os = "linux")]
pub use tun::{read_one_packet, run_tun_poc};
