//! Unprivileged CLI and terminal interface. Closing this program has no firewall side effects.

mod capture_command;
mod config_command;
mod identity_command;
mod journal_command;
mod tui;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use tunlatch_core::config::DesiredProtection;
use tunlatch_core::control::{SimulationRequest, SimulationStatus};
use tunlatch_ipc::{
    query_network_status, query_simulation, query_status, query_system_network_status,
    query_system_status, submit_simulation,
};

#[derive(Parser)]
#[command(
    version,
    about = "TunLatch macOS firewall framework (PF enforcement not yet available)"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Query a fresh service snapshot. Failure returns a nonzero exit code.
    Status {
        #[arg(long, required_unless_present = "system", conflicts_with = "system")]
        runtime_dir: Option<PathBuf>,
        /// Query the fixed root-owned system endpoint if a system service is available.
        #[arg(long)]
        system: bool,
        #[arg(long)]
        json: bool,
        /// Request extended scan diagnostics from a supporting service.
        #[arg(long)]
        network_details: bool,
    },
    /// Open the read-only terminal dashboard (q: quit, r: refresh).
    Tui {
        #[arg(long)]
        runtime_dir: PathBuf,
    },
    /// Offline configuration and user-private simulation tools.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Exercise the opt-in in-memory controller. Actual protection remains unknown.
    Simulate {
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[command(subcommand)]
        command: SimulationCommand,
    },
    /// Inspect minimal process metadata without granting trust or changing the service.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Read one PID twice; FD, loaded-image and TUN ownership remain unverified.
    Inspect {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        json: bool,
        /// Include bounded raw FD/control metadata; this still does not establish ownership.
        #[arg(long)]
        fd_details: bool,
    },
    /// Check a running process against an expected CodeDirectory fingerprint; never grants trust.
    CheckImage {
        #[arg(long)]
        pid: u32,
        /// Expected 20-byte CDHash (40 hex digits), not a whole-file SHA-256 or an approval.
        #[arg(long, value_parser = identity_command::parse_cdhash)]
        cdhash: [u8; 20],
        #[arg(long)]
        json: bool,
    },
    /// Correlate a running process and utun interface as an untrusted candidate.
    Correlate {
        #[arg(long)]
        pid: u32,
        /// Expected 20-byte CDHash (40 hex digits), not an approval.
        #[arg(long, value_parser = identity_command::parse_cdhash)]
        cdhash: [u8; 20],
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SimulationCommand {
    /// Query the isolated simulation, without changing it.
    Status,
    /// Submit one simulated intent with an explicit retry ID and expected generation.
    Set {
        desired: SimulationIntent,
        #[arg(long)]
        operation_id: u64,
        #[arg(long)]
        expected_generation: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SimulationIntent {
    Enabled,
    Disabled,
}

impl From<SimulationIntent> for DesiredProtection {
    fn from(value: SimulationIntent) -> Self {
        match value {
            SimulationIntent::Enabled => Self::Enabled,
            SimulationIntent::Disabled => Self::Disabled,
        }
    }
}

fn print_simulation(status: SimulationStatus, json: bool) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "actual_protection": "unknown", "simulation": status,
            }))?
        );
    } else {
        println!("Simulation only; actual protection remains UNKNOWN. No PF changes.");
        println!(
            "Generation: {}; desired: {:?}; committed: {:?}; observed: {:?}",
            status.generation, status.desired, status.committed, status.observed
        );
    }
    Ok(())
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Validate schema, version, size and fields in a TOML file.
    Check { path: PathBuf },
    /// Preview a bounded PF blocking candidate. No rules are loaded or authorized.
    CompilePreview {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print the fixed deployment layout and launchd template as preview JSON.
    DeploymentPreview,
    /// Store a local simulation intent and exercise modeled submission and readback.
    JournalPreview {
        path: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Read a local simulation intent as a recovery hint.
    JournalStatus {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare existing PF capture files with an offline candidate.
    VerifyCapture {
        path: PathBuf,
        #[arg(long)]
        capture_dir: PathBuf,
        #[arg(long)]
        anchor: String,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=300))]
        max_age_secs: u64,
        #[arg(long)]
        json: bool,
    },
    /// Preview a configuration draft without applying it or importing approval.
    ImportPreview {
        path: PathBuf,
        /// Optional current draft to compare with the incoming draft.
        #[arg(long)]
        current: Option<PathBuf>,
    },
    /// Export a normalized draft without changing the service configuration.
    Export {
        source: PathBuf,
        output: PathBuf,
        /// Explicitly replace an existing regular output file.
        #[arg(long)]
        overwrite: bool,
    },
    /// Print the documented initial configuration.
    Example,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::Status {
            runtime_dir,
            system: _,
            json,
            network_details,
        } => {
            let status = match (runtime_dir.as_deref(), network_details) {
                (Some(dir), false) => query_status(dir).await.map(|status| (status, None)),
                (None, false) => query_system_status().await.map(|status| (status, None)),
                (Some(dir), true) => query_network_status(dir)
                    .await
                    .map(|(status, observation)| (status, Some(observation))),
                (None, true) => query_system_network_status()
                    .await
                    .map(|(status, observation)| (status, Some(observation))),
            };
            let (status, observation) =
                status.context("cannot obtain current status; protection is unknown")?;
            if json {
                let output = match observation {
                    Some(observation) => {
                        serde_json::json!({"status": status, "network_observation": observation})
                    }
                    None => serde_json::to_value(&status)?,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Protection: UNKNOWN — PF backend not implemented");
                println!(
                    "Desired: {:?}; committed: {:?}",
                    status.desired, status.committed
                );
                println!(
                    "Discovered interfaces: {}; trusted TUN: none",
                    status.interfaces.len()
                );
                if let Some(observation) = observation {
                    println!(
                        "Network scan: generation {}; on-demand rescan",
                        observation.generation
                    );
                }
            }
        }
        Command::Tui { runtime_dir } => tui::run(&runtime_dir).await?,
        Command::Identity {
            command:
                IdentityCommand::Inspect {
                    pid,
                    json,
                    fd_details,
                },
        } => {
            identity_command::inspect(pid, json, fd_details).await?;
        }
        Command::Identity {
            command: IdentityCommand::CheckImage { pid, cdhash, json },
        } => identity_command::check_image(pid, cdhash, json).await?,
        Command::Identity {
            command: IdentityCommand::Correlate { pid, cdhash, json },
        } => identity_command::correlate(pid, cdhash, json).await?,
        Command::Simulate {
            runtime_dir,
            json,
            command,
        } => {
            let status = match command {
                SimulationCommand::Status => query_simulation(&runtime_dir).await?,
                SimulationCommand::Set {
                    desired,
                    operation_id,
                    expected_generation,
                } => {
                    submit_simulation(
                        &runtime_dir,
                        SimulationRequest {
                            desired: desired.into(),
                            operation_id,
                            expected_generation,
                        },
                    )
                    .await?
                }
            };
            print_simulation(status, json)?;
        }
        Command::Config {
            command: ConfigCommand::Check { path },
        } => {
            println!("{}", config_command::check(&path)?);
        }
        Command::Config {
            command: ConfigCommand::CompilePreview { path, json },
        } => println!("{}", config_command::compile_preview(&path, json)?),
        Command::Config {
            command: ConfigCommand::DeploymentPreview,
        } => println!(
            "{}",
            serde_json::to_string_pretty(&tunlatch_platform::launchd::deployment_preview())?
        ),
        Command::Config {
            command:
                ConfigCommand::JournalPreview {
                    path,
                    state_dir,
                    json,
                },
        } => {
            tokio::task::spawn_blocking(move || journal_command::preview(&path, &state_dir, json))
                .await??;
        }
        Command::Config {
            command: ConfigCommand::JournalStatus { state_dir, json },
        } => {
            tokio::task::spawn_blocking(move || journal_command::inspect(&state_dir, json))
                .await??;
        }
        Command::Config {
            command:
                ConfigCommand::VerifyCapture {
                    path,
                    capture_dir,
                    anchor,
                    max_age_secs,
                    json,
                },
        } => {
            tokio::task::spawn_blocking(move || {
                capture_command::verify(&path, &capture_dir, &anchor, max_age_secs, json)
            })
            .await??;
        }
        Command::Config {
            command: ConfigCommand::ImportPreview { path, current },
        } => {
            println!(
                "{}",
                config_command::import_preview(&path, current.as_deref())?
            );
        }
        Command::Config {
            command:
                ConfigCommand::Export {
                    source,
                    output,
                    overwrite,
                },
        } => {
            println!("{}", config_command::export(&source, &output, overwrite)?);
        }
        Command::Config {
            command: ConfigCommand::Example,
        } => {
            print!("{}", include_str!("../../../examples/config.toml"));
        }
    }
    Ok(())
}
