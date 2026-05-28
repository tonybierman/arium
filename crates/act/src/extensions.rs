use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub struct Extension {
    pub name: String,
    pub path: PathBuf,
}

/// Walk every directory on `PATH` and collect executables named
/// `{tool}-<sub>`. First hit wins per name (POSIX PATH-resolution order),
/// alphabetised on output.
pub fn discover(tool: &str) -> Vec<Extension> {
    let prefix = format!("{tool}-");
    let mut by_name: BTreeMap<String, PathBuf> = BTreeMap::new();

    let Some(path_var) = env::var_os("PATH") else {
        return Vec::new();
    };

    for dir in env::split_paths(&path_var) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let stem = name.strip_suffix(std::env::consts::EXE_SUFFIX).unwrap_or(name);
            let Some(sub) = stem.strip_prefix(&prefix) else {
                continue;
            };
            if sub.is_empty() {
                continue;
            }
            let full = entry.path();
            if !is_executable_file(&full) {
                continue;
            }
            by_name.entry(sub.to_string()).or_insert(full);
        }
    }

    by_name
        .into_iter()
        .map(|(name, path)| Extension { name, path })
        .collect()
}

/// Find a single `{tool}-{sub}` executable on PATH.
pub fn find(tool: &str, sub: &str) -> Option<PathBuf> {
    let target_stem = format!("{tool}-{sub}");
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        for candidate in candidate_names(&target_stem) {
            let p = dir.join(&candidate);
            if is_executable_file(&p) {
                return Some(p);
            }
        }
    }
    None
}

fn candidate_names(stem: &str) -> Vec<String> {
    let mut v = vec![stem.to_string()];
    let suffix = std::env::consts::EXE_SUFFIX;
    if !suffix.is_empty() {
        v.push(format!("{stem}{suffix}"));
    }
    v
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Resolve `{tool}-{sub}` on PATH and hand control to it. On success on Unix
/// this never returns (the host is replaced); on Windows the child is
/// awaited and its status is propagated.
///
/// `env_overrides` are layered on top of the inherited environment, so the
/// child sees its parent's vars plus whatever the gate injected
/// (`ACT_USER_ID`, `ACT_DATABASE_URL`, ...).
pub fn dispatch(
    tool: &str,
    sub: &str,
    extra: &[OsString],
    env_overrides: &[(String, String)],
) -> ExitCode {
    let Some(exe) = find(tool, sub) else {
        print_unknown_subcommand(tool, sub);
        return ExitCode::from(127);
    };
    exec_replace(&exe, extra, env_overrides)
}

fn print_unknown_subcommand(tool: &str, sub: &str) {
    eprintln!("error: unknown subcommand '{sub}'");
    eprintln!();
    let found = discover(tool);
    if found.is_empty() {
        eprintln!("No `{tool}-*` extensions found on PATH.");
    } else {
        eprintln!("Available extensions:");
        for ext in found {
            eprintln!("  {tool}-{}", ext.name);
        }
    }
}

#[cfg(unix)]
fn exec_replace(exe: &Path, extra: &[OsString], env_overrides: &[(String, String)]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let mut cmd = Command::new(exe);
    cmd.args(extra);
    for (k, v) in env_overrides {
        cmd.env(k, v);
    }
    // `exec` returns only on failure. On success the child has replaced
    // this process and we never get here.
    let err = cmd.exec();
    eprintln!("error: failed to exec {}: {err}", exe.display());
    ExitCode::from(1)
}

#[cfg(windows)]
fn exec_replace(exe: &Path, extra: &[OsString], env_overrides: &[(String, String)]) -> ExitCode {
    use std::process::Command;

    let mut cmd = Command::new(exe);
    cmd.args(extra);
    for (k, v) in env_overrides {
        cmd.env(k, v);
    }
    match cmd.status() {
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            let byte = u8::try_from(code).unwrap_or(1);
            ExitCode::from(byte)
        }
        Err(e) => {
            eprintln!("error: failed to spawn {}: {e}", exe.display());
            ExitCode::from(1)
        }
    }
}
