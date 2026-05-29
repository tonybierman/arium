//! The `act` binary — a generic, `dotnet`-style host that discovers
//! `act-<sub>` executables on `PATH` (and next to its own binary) and
//! execs into them. The host has no opinion about auth, the database,
//! or arium itself; each extension owns its own gate via the
//! `arium_act::gate` SDK.
//!
//! Subcommands:
//!
//! - `act extensions [--paths]` — list discovered extensions
//! - `act <sub> [args...]` — exec into `act-<sub>` with the remaining args
//!
//! Discovery order matches the convention used by `dotnet` and `kubectl`:
//! the directory containing the running `act` binary first (so sibling
//! `cargo build` outputs work without staging anything on `$PATH`), then
//! every entry on `$PATH`. See the `extensions` module for the exact rules.

mod extensions;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Arg, ArgAction, Command};

const TOOL_NAME: &str = "act";

fn cli() -> Command {
    Command::new(TOOL_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .about("Extensible CLI host for arium.")
        .long_about(
            "Discovers and runs `act-<sub>` executables on PATH (and next \
             to this binary). The host does not authenticate; each \
             extension owns its own auth/admin gate — see \
             `arium_act::gate` for the SDK extensions use to plug in.",
        )
        .subcommand_required(false)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("extensions")
                .about("List `act-*` extensions discovered on PATH.")
                .arg(
                    Arg::new("paths")
                        .long("paths")
                        .help("Print the full path of each extension binary.")
                        .action(ArgAction::SetTrue),
                ),
        )
}

fn main() -> ExitCode {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("extensions", sub)) => {
            let show_paths = sub.get_flag("paths");
            let found = extensions::discover(TOOL_NAME);
            if found.is_empty() {
                eprintln!("No `{TOOL_NAME}-*` extensions found on PATH.");
                return ExitCode::from(0);
            }
            for ext in found {
                if show_paths {
                    println!("{TOOL_NAME}-{}\t{}", ext.name, ext.path.display());
                } else {
                    println!("{TOOL_NAME}-{}", ext.name);
                }
            }
            ExitCode::from(0)
        }
        Some((external, sub)) => {
            let extra: Vec<OsString> = sub
                .get_many::<OsString>("")
                .map(|v| v.cloned().collect())
                .unwrap_or_default();
            extensions::dispatch(TOOL_NAME, external, &extra, &[])
        }
        None => {
            let _ = cli().print_help();
            println!();
            ExitCode::from(2)
        }
    }
}
