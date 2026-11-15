//! Foreground observer and an explicit privileged, block-only PF session.

mod pf_control;

use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use tunlatch_core::config::Config;
use tunlatch_ipc::endpoint::ServerSocket;
use tunlatch_platform::config;

#[derive(Parser)]
#[command(version, about = "TunLatch foreground observer and initial PF backend")]
struct Args {
    /// Existing private directory (0700), shared with the current user's CLI/TUI.
    #[arg(
        long,
        required_unless_present = "pf_block_interface",
        conflicts_with = "pf_block_interface"
    )]
    runtime_dir: Option<PathBuf>,
    /// Validate and read initial intent; never applied to PF or rewritten.
    #[arg(long, conflicts_with = "pf_block_interface")]
    config: Option<PathBuf>,
    /// Enable a separate in-memory simulation controller. Never changes PF or configuration.
    #[arg(long, conflicts_with = "pf_block_interface")]
    simulation: bool,
    /// Attach a block-all-outbound rule to this interface. SIGINT explicitly requests removal;
    /// SIGTERM exits without removing PF. Root only; requires the protected installed daemon
    /// and initially disabled PF. Connectivity may be interrupted; this is not complete protection.
    #[arg(long, value_name = "INTERFACE")]
    pf_block_interface: Option<String>,
    /// Also expose the fixed system sockets to this non-root UID and root control clients.
    #[arg(long, requires = "pf_block_interface", value_name = "UID")]
    pf_system_owner_uid: Option<NonZeroU32>,
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
    if let Some(interface) = args.pf_block_interface {
        if let Some(owner) = args.pf_system_owner_uid {
            return pf_control::run(interface, owner).await;
        }
        return run_blocking_session(&interface).await;
    }
    if nix::unistd::geteuid().is_root() {
        bail!(
            "the development observer must run as a normal user; use the explicit PF mode for privileged sessions"
        );
    }
    let config = match args.config {
        Some(path) => config::load(&path).context("configuration rejected; service not started")?,
        None => Config::default(),
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let runtime_dir = args.runtime_dir.context("runtime directory is required")?;
    let socket = ServerSocket::bind(&runtime_dir)
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

async fn run_blocking_session(interface: &str) -> anyhow::Result<()> {
    use tunlatch_platform::pf::session::BlockingSession;

    // Register both handlers before the first PF mutation, including while the synchronous
    // startup sequence is in progress. A later SIGKILL or crash still cannot be caught.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut session = match BlockingSession::start(interface) {
        Ok(session) => session,
        Err(error) => {
            let (cause, interrupted) = error.into_parts();
            if let Some(interrupted) = interrupted {
                eprintln!(
                    "PF startup interrupted at {:?}: {cause}",
                    interrupted.phase()
                );
                match interrupted.inspect() {
                    Ok(report) => eprintln!("PF diagnostic: {report:?}"),
                    Err(error) => eprintln!("PF diagnostic unavailable: {error}"),
                }
                eprintln!(
                    "The session is retained for diagnosis. SIGINT or SIGTERM exits without changing PF and releases the record lock."
                );
                tokio::select! {
                    _ = interrupt.recv() => {},
                    _ = terminate.recv() => {},
                }
                drop(interrupted);
            }
            return Err(anyhow::Error::new(cause).context("PF startup failed"));
        }
    };
    eprintln!(
        "PF block rule attached on {interface}; protection remains unknown. SIGINT requests removal; SIGTERM exits without changing PF."
    );
    loop {
        let signal = tokio::select! {
            result = interrupt.recv() => {
                result.context("interrupt handler closed; PF remains unchanged")?;
                SessionSignal::ExplicitStop
            },
            result = terminate.recv() => {
                result.context("termination handler closed; PF remains unchanged")?;
                SessionSignal::Exit
            },
        };
        match handle_session_signal(signal, || session.stop()) {
            Ok(SessionAction::Stopped) => {
                eprintln!(
                    "PF session detached, its reference released, and completed records removed."
                );
                return Ok(());
            }
            Ok(SessionAction::Exited) => {
                eprintln!(
                    "Service exiting without changing PF; records are retained for diagnosis."
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!(
                    "PF shutdown failed: {error}; phase: {:?}. SIGINT retries only when safe; SIGTERM exits without changing PF.",
                    session.status()
                );
                match session.inspect() {
                    Ok(report) => eprintln!("PF diagnostic: {report:?}"),
                    Err(error) => eprintln!("PF diagnostic unavailable: {error}"),
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SessionSignal {
    ExplicitStop,
    Exit,
}

#[derive(Debug, Eq, PartialEq)]
enum SessionAction {
    Stopped,
    Exited,
}

fn handle_session_signal<E>(
    signal: SessionSignal,
    stop: impl FnOnce() -> Result<(), E>,
) -> Result<SessionAction, E> {
    match signal {
        SessionSignal::ExplicitStop => {
            stop()?;
            Ok(SessionAction::Stopped)
        }
        SessionSignal::Exit => Ok(SessionAction::Exited),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_mode_is_explicit_and_cannot_mix_with_observer_options() {
        assert!(Args::try_parse_from(["tunlatchd"]).is_err());
        assert!(Args::try_parse_from(["tunlatchd", "--pf-block-interface", "en0"]).is_ok());
        assert!(
            Args::try_parse_from([
                "tunlatchd",
                "--pf-block-interface",
                "en0",
                "--pf-system-owner-uid",
                "501"
            ])
            .is_ok()
        );
        assert!(Args::try_parse_from(["tunlatchd", "--pf-system-owner-uid", "501"]).is_err());
        assert!(
            Args::try_parse_from([
                "tunlatchd",
                "--pf-block-interface",
                "en0",
                "--pf-system-owner-uid",
                "0"
            ])
            .is_err()
        );
        assert!(Args::try_parse_from(["tunlatchd", "--runtime-dir", "/tmp/run"]).is_ok());
        for option in ["--simulation", "--config", "--runtime-dir"] {
            let mut args = vec!["tunlatchd", "--pf-block-interface", "en0", option];
            if option != "--simulation" {
                args.push("/tmp/value");
            }
            assert!(Args::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn termination_exits_without_requesting_pf_shutdown() -> Result<(), &'static str> {
        let calls = std::cell::Cell::new(0);
        let stop = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        assert_eq!(
            handle_session_signal(SessionSignal::Exit, stop)?,
            SessionAction::Exited
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            handle_session_signal(SessionSignal::ExplicitStop, stop)?,
            SessionAction::Stopped
        );
        assert_eq!(calls.get(), 1);
        Ok(())
    }
}
