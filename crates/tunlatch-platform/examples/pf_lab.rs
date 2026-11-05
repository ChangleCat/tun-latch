//! Standalone ordinary-user PF laboratory preparation. All live PF requests are disabled.

#[path = "../tests/pf_lab/mod.rs"]
mod pf_lab;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pf_lab::plan;

#[derive(Parser)]
#[command(about = "Ordinary-user preparation only; every live PF request is disabled")]
struct Arguments {
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// Print the exact, fixed plan. No system command is run.
    Plan,
    /// Copy this executable and recovery material into an existing empty private directory.
    Prepare { output: PathBuf },
    /// Verify a prepared package's files, path ACL observations and journal without PF access.
    Audit { directory: PathBuf },
    /// Unavailable: always refuses until safe bootstrap, ownership and supervision exist.
    ClaimRecovery {
        #[arg(long)]
        live_pf: bool,
        #[arg(long)]
        approved_isolated_lab: bool,
        #[arg(long)]
        approval_id: String,
    },
    /// Show the disabled recovery candidate; any live request is refused.
    Recover {
        #[arg(long)]
        live_pf: bool,
        #[arg(long)]
        approved_isolated_lab: bool,
    },
}

fn run(arguments: Arguments) -> pf_lab::Result<()> {
    match arguments.command.unwrap_or(Action::Plan) {
        Action::Plan => println!("{}", serde_json::to_string_pretty(&plan())?),
        Action::Prepare { output } => {
            pf_lab::prepare_bundle(&output)?;
            println!("Bundle prepared without PF access: {}", output.display());
        }
        Action::Audit { directory } => {
            let audit = pf_lab::package::audit(&directory)?;
            println!("{}", serde_json::to_string_pretty(&audit)?);
            if audit.result != "ordinary_bundle_verified" {
                return Err(pf_lab::LabError::Refused(
                    "unsettled package journal; no cleanup authority",
                ));
            }
        }
        Action::ClaimRecovery {
            live_pf,
            approved_isolated_lab,
            approval_id: _,
        } => return Err(pf_lab::live_rejection(live_pf, approved_isolated_lab)),
        Action::Recover {
            live_pf: false,
            approved_isolated_lab: false,
        } => println!("{}", serde_json::to_string_pretty(&plan()["recovery"])?),
        Action::Recover {
            live_pf,
            approved_isolated_lab,
        } => {
            return Err(pf_lab::live_rejection(live_pf, approved_isolated_lab));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
