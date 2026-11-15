//! CLI and terminal interface, including explicit privileged PF-session control.

mod config_command;
mod identity_command;
mod journal_command;
mod tui;

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use tunlatch_core::config::DesiredProtection;
use tunlatch_core::control::{SimulationRequest, SimulationStatus};
use tunlatch_ipc::{
    PfStartResult, PfStopResult, query_network_status, query_pf_session, query_simulation,
    query_status, query_system_network_status, query_system_status, start_pf_session,
    stop_pf_session, submit_simulation,
};

#[derive(Parser)]
#[command(
    version,
    about = "TunLatch macOS firewall framework (protection not yet verified)"
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
    /// Inspect PF, control the live block-only session, or clean validated local records.
    Pf {
        #[command(subcommand)]
        command: PfCommand,
    },
}

#[derive(Subcommand)]
enum PfCommand {
    /// Read the daemon's last local PF-session checkpoint; protection remains unknown.
    SessionStatus {
        #[arg(long)]
        json: bool,
    },
    /// Start the same preconfigured block-only session again after its verified shutdown.
    Start,
    /// Ask the root-only endpoint to stop its live block-only session.
    Stop,
    /// Read PF status, starter references, or filter rules.
    Inspect {
        #[arg(value_enum)]
        what: PfInspection,
        /// Session ID for an anchor-rules query.
        #[arg(long)]
        session: Option<String>,
    },
    /// Finish local record retirement after an independently verified PF reference release.
    /// This never changes PF and requires root and the fixed protected store.
    FinishRetirement,
    /// Discard one prior boot's validated local PF records without changing current PF.
    DiscardPreviousBoot,
}

#[derive(Clone, Copy, ValueEnum)]
enum PfInspection {
    Info,
    References,
    RootRules,
    AnchorRules,
    /// Cross-check native root filter reads against independent pfctl output.
    NativeRoot,
    /// Inspect the protected PF reference receipt and current inventory.
    ReferenceRecord,
    /// Inspect recovery records and compare them with current PF observations.
    Recovery,
}

fn inspect_pf(what: PfInspection, session: Option<String>) -> anyhow::Result<()> {
    use tunlatch_platform::pf::snapshot::{Query, query};

    let choice = match (what, session.as_deref()) {
        (PfInspection::Info, None) => Query::Info,
        (PfInspection::References, None) => Query::References,
        (PfInspection::RootRules, None) => Query::RootRules,
        (PfInspection::AnchorRules, Some(session)) => Query::AnchorRules { session },
        (PfInspection::AnchorRules, None) => anyhow::bail!("anchor-rules requires --session"),
        (_, Some(_)) => anyhow::bail!("--session is only valid with anchor-rules"),
        (PfInspection::NativeRoot, None) => {
            let result = tunlatch_platform::pf::qualification::check_root_filter()
                .context("native PF qualification failed; protection remains unknown")?;
            println!(
                "native and pfctl root filter reads agree: {} rules; protection remains unknown",
                result.filter_rules
            );
            return Ok(());
        }
        (PfInspection::ReferenceRecord, None) => {
            use tunlatch_platform::pf::reference_acquire::{ReferenceRecordStatus, inspect_record};
            let status = inspect_record()
                .context("cannot inspect PF reference record; protection remains unknown")?;
            let description = match status {
                ReferenceRecordStatus::RetirementPending => {
                    "verified-release record retirement is unfinished"
                }
                ReferenceRecordStatus::ReleaseRecordPresent => {
                    "release record exists; outcome requires reconciliation"
                }
                ReferenceRecordStatus::AnchorRecordPresent => {
                    "anchor or hook record exists; outcome requires reconciliation"
                }
                ReferenceRecordStatus::Missing => "no reference acquisition record",
                ReferenceRecordStatus::AcquisitionUnconfirmed => "acquisition outcome unconfirmed",
                ReferenceRecordStatus::RecordedBootDiffers => "record belongs to a different boot",
                ReferenceRecordStatus::ReferencePresent => {
                    "recorded reference appears in current inventory"
                }
                ReferenceRecordStatus::ReferenceAbsent => {
                    "recorded reference is absent from current inventory"
                }
            };
            println!("{description}; protection remains unknown");
            return Ok(());
        }
        (PfInspection::Recovery, None) => {
            let report = tunlatch_platform::pf::recovery::inspect()
                .context("cannot inspect PF recovery state; protection remains unknown")?;
            println!("boot: {:?}", report.boot);
            if let Some(remaining) = report.retirement_remaining {
                println!("verified-release record retirement pending: {remaining} records remain");
                println!("diagnostic only; current PF state and protection remain unknown");
                return Ok(());
            }
            println!(
                "initial PF: {:?}, starter references: {:?}",
                report.initial_pf, report.initial_reference_count
            );
            println!(
                "records: acquire={:?}, stage={:?}, hook={:?}, removal={:?}, clear={:?}, release={:?}",
                report.acquisition,
                report.stage,
                report.hook,
                report.removal,
                report.clear,
                report.release
            );
            println!(
                "observed: reference={:?}, hook={:?}, anchor={:?}",
                report.reference_observation, report.hook_observation, report.anchor_observation
            );
            println!("diagnostic only; protection remains unknown");
            return Ok(());
        }
    };
    let output = query(choice).context("cannot read PF; protection remains unknown")?;
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
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
        Command::Pf {
            command: PfCommand::SessionStatus { json },
        } => {
            let status = query_pf_session()
                .await
                .context("cannot obtain PF session checkpoint; protection remains unknown")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "PF session phase: {:?}; last stop: {:?}",
                    status.phase, status.last_stop
                );
                println!("Local checkpoint only; current PF state and protection remain unknown.");
            }
        }
        Command::Pf {
            command: PfCommand::Start,
        } => {
            anyhow::ensure!(
                nix::unistd::geteuid().is_root(),
                "PF start requires effective UID 0; no request was sent"
            );
            let result = start_pf_session().await.map_err(|error| match error {
                tunlatch_ipc::IpcError::Remote(_) => anyhow::anyhow!("PF start was rejected: {error}"),
                _ => anyhow::anyhow!("PF start exchange failed: {error}; the request may have been accepted, so check pf session-status before another request"),
            })?;
            match result {
                PfStartResult::Accepted => println!(
                    "PF start accepted; check pf session-status for its result. Protection remains unknown."
                ),
                PfStartResult::AlreadyAttached => println!(
                    "The last verified session phase is already attached; current PF state and protection remain unknown."
                ),
            }
        }
        Command::Pf {
            command: PfCommand::Stop,
        } => {
            anyhow::ensure!(
                nix::unistd::geteuid().is_root(),
                "PF stop requires effective UID 0; no request was sent"
            );
            let result = stop_pf_session().await.map_err(|error| match error {
                tunlatch_ipc::IpcError::Remote(_) => anyhow::anyhow!("PF stop was rejected: {error}"),
                _ => anyhow::anyhow!("PF stop exchange failed: {error}; the request may have been accepted, so check pf session-status before another request"),
            })?;
            match result {
                PfStopResult::Accepted => println!(
                    "PF stop accepted; check pf session-status for its result. Protection remains unknown."
                ),
                PfStopResult::AlreadyStopped => println!(
                    "This live session already completed shutdown; protection remains unknown."
                ),
            }
        }
        Command::Pf {
            command: PfCommand::Inspect { what, session },
        } => tokio::task::spawn_blocking(move || inspect_pf(what, session)).await??,
        Command::Pf {
            command: PfCommand::FinishRetirement,
        } => {
            let finished =
                tokio::task::spawn_blocking(tunlatch_platform::pf::retirement::finish_completed)
                    .await??;
            if finished {
                println!("completed PF session records retired; PF was not changed");
            } else {
                println!("no completed PF session retirement marker; PF was not changed");
            }
        }
        Command::Pf {
            command: PfCommand::DiscardPreviousBoot,
        } => {
            let count =
                tokio::task::spawn_blocking(tunlatch_platform::pf::recovery::discard_previous_boot)
                    .await??;
            println!("discarded {count} previous-boot PF records; current PF was not changed");
        }
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
