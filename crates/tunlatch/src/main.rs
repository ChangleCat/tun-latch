//! Unprivileged CLI and terminal interface. Closing this program has no firewall side effects.

mod tui;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tunlatch_core::config::DesiredProtection;
use tunlatch_ipc::query_status;

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
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Validate schema, version, size and fields in a TOML file.
    Check { path: PathBuf },
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
        Command::Config {
            command: ConfigCommand::Check { path },
        } => {
            let config =
                tunlatch_platform::config::load(&path).context("configuration rejected")?;
            println!(
                "Configuration valid; desired = {:?}. No changes applied.",
                config.desired()
            );
            if config.desired() == DesiredProtection::Enabled {
                println!("Protection remains UNKNOWN: PF enforcement is not implemented.");
            }
        }
        Command::Config {
            command: ConfigCommand::Example,
        } => {
            print!("{}", include_str!("../../../examples/config.toml"));
        }
    }
    Ok(())
}
