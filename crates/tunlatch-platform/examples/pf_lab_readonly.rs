//! Operator-run read-only PF inventory; the project executable itself never runs as root.
#[allow(dead_code)]
#[path = "../tests/pf_lab/process.rs"]
mod process;
#[path = "../tests/pf_lab/readonly.rs"]
mod readonly;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    about = "Read-only PF preflight. Run as your normal user; fixed system queries use sudo -n."
)]
struct Arguments {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Plan,
    Collect {
        #[arg(long)]
        output: PathBuf,
    },
}

fn run() -> readonly::Result<bool> {
    let value = match Arguments::parse().command {
        Action::Plan => readonly::plan(),
        Action::Collect { output } => readonly::collect(&output, &mut readonly::SystemReader)?,
    };
    let complete = value["result"] != "incomplete";
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(complete)
}
fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
