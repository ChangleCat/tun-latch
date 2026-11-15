//! macOS adapter boundary. The explicit PF session can write PF when run by the installed root
//! daemon; this crate does not install a service or perform implicit privilege escalation.

#[cfg(not(target_os = "macos"))]
compile_error!("TunLatch currently supports macOS only; no fallback firewall is available");

pub mod config;
pub mod events;
pub mod identity;
pub mod launchd;
pub mod network;
pub mod pf;
pub mod pf_apply;
pub mod policy_compile;
pub mod store;
