//! Foreground development daemon. Running as root is deliberately unsupported at this stage.

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use tunlatch_core::config::Config;
use tunlatch_ipc::endpoint::ServerSocket;
use tunlatch_platform::config;

#[derive(Parser)]
#[command(
    version,
    about = "Read-only TunLatch development service; does not enforce PF protection"
)]
struct Args {
    /// Existing private directory (0700), shared with the current user's CLI/TUI.
    #[arg(long)]
    runtime_dir: PathBuf,
    /// Validate and read initial intent; never applied to PF or rewritten.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Enable a separate in-memory simulation controller. Never changes PF or configuration.
    #[arg(long)]
    simulation: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| anyhow::anyhow!("cannot initialize diagnostics: {error}"))?;
    if nix::unistd::geteuid().is_root() {
        bail!(
            "the development observer must run as a normal user; privileged PF service is not implemented"
        );
    }
    let config = match args.config {
        Some(path) => config::load(&path).context("configuration rejected; service not started")?,
        None => Config::default(),
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let socket = ServerSocket::bind(&args.runtime_dir)
        .context("cannot bind private endpoint; existing paths are preserved")?;
    tracing::info!(
        mode = if args.simulation {
            "simulation"
        } else {
            "observer"
        },
        "service started; protection is unknown, PF backend is unavailable"
    );
    let shutdown = async move {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _signal = terminate.recv() => Ok(()),
        }
    };
    if args.simulation {
        tunlatchd::serve_simulation(socket, config, shutdown).await
    } else {
        tunlatchd::serve(socket, config, shutdown).await
    }
}
