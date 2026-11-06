//! macOS adapter boundary. No PF writes, service installation, or implicit privilege escalation.

#[cfg(not(target_os = "macos"))]
compile_error!("TunLatch currently supports macOS only; no fallback firewall is available");

pub mod config;
pub mod events;
pub mod identity;
pub mod network;
pub mod pf;
pub mod policy_compile;
