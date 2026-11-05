//! Unprivileged CLI and terminal interface. Closing this program has no firewall side effects.

mod config_command;
mod tui;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use tunlatch_core::config::DesiredProtection;
use tunlatch_core::control::{SimulationRequest, SimulationStatus};
use tunlatch_ipc::{query_simulation, query_status, submit_simulation};

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
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Open the read-only terminal dashboard (q: quit, r: refresh).
    Tui {
        #[arg(long)]
        runtime_dir: PathBuf,
    },
    /// Offline configuration tools. These never change protection or stored configuration.
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
        Command::Status { runtime_dir, json } => {
            let status = query_status(&runtime_dir)
                .await
                .context("cannot obtain current status; protection is unknown")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
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
            }
        }
        Command::Tui { runtime_dir } => tui::run(&runtime_dir).await?,
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
