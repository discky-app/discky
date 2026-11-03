//! Developer tasks for the Discky workspace, run as `cargo xtask <command>`:
//!
//! - `icon`: render the pixel logo into `assets/AppIcon.icns` and `assets/logo.png`.
//! - `bundle [--release]`: build `target/Discky.app` (always a release build) and sign it.
//! - `install`: `bundle`, then copy the app to `/Applications/Discky.app`.

mod bundle;
mod icon;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const USAGE: &str = "usage: cargo xtask <icon | bundle [--release] | install>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("icon") => icon::run(&workspace_root()),
        Some("bundle") => bundle::run(&workspace_root(), &args[1..]).map(|_| ()),
        Some("install") => bundle::install(&workspace_root()),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The workspace root: two levels above this crate's manifest.
fn workspace_root() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.ancestors()
        .nth(2)
        .map_or_else(|| here.to_path_buf(), Path::to_path_buf)
}

/// Cargo's target directory: `CARGO_TARGET_DIR` if set (relative to the root), else
/// `<root>/target`.
fn target_dir(root: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => root.join(dir),
        None => root.join("target"),
    }
}

/// `cmd` rendered for error messages: program and arguments separated by spaces.
fn describe(cmd: &Command) -> String {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run `cmd` with no stdin and captured output; returns its stdout on success, or an
/// error naming the command with its stderr.
fn run_capture(cmd: &mut Command) -> Result<String, String> {
    let shown = describe(cmd);
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("`{shown}` could not start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`{shown}` failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim_end()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run `cmd` with all stdio inherited (for long builds whose output the user watches).
fn run_inherit(cmd: &mut Command) -> Result<(), String> {
    let shown = describe(cmd);
    let status = cmd
        .status()
        .map_err(|e| format!("`{shown}` could not start: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{shown}` failed ({status}); see its output above"))
    }
}
