//! External tools: where a cleanup command's binary lives, and which apps are running.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Directories searched after `$PATH`: a GUI-launched process often has a bare `PATH`.
fn extra_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        let home = PathBuf::from(home);
        dirs.push(home.join(".cargo/bin"));
        dirs.push(home.join(".local/bin"));
    }
    dirs
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn lookup(name: &str) -> Option<PathBuf> {
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    path_dirs
        .into_iter()
        .chain(extra_dirs())
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

/// Whether `cargo cache --version` exits 0; asked once per process.
fn cargo_cache_installed() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        let Some(cargo) = lookup("cargo") else {
            return false;
        };
        Command::new(cargo)
            .args(["cache", "--version"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Absolute path of the executable `name`: `$PATH`, then `/opt/homebrew/bin`,
/// `/usr/local/bin`, `~/.cargo/bin`, `~/.local/bin`. `cargo-cache` is a cargo subcommand:
/// it counts as installed when `cargo cache --version` succeeds, and resolves to its own
/// binary when found, else to `cargo`.
pub fn tool_path(name: &str) -> Option<PathBuf> {
    if name == "cargo-cache" {
        if !cargo_cache_installed() {
            return None;
        }
        return lookup(name).or_else(|| lookup("cargo"));
    }
    lookup(name)
}

/// Whether a rule command's `tool` cannot be found (see [`tool_path`]).
pub fn is_tool_missing(tool: &str) -> bool {
    tool_path(tool).is_none()
}

/// Bundle ids of running apps: one `ps -axo comm=` call, each `/…/X.app/Contents/MacOS/…`
/// executable mapped to `X.app/Contents/Info.plist`'s `CFBundleIdentifier`. Nothing is
/// cached; on any failure the set is just smaller.
pub fn running_app_bundle_ids() -> HashSet<String> {
    let Ok(out) = Command::new("ps")
        .args(["-axo", "comm="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return HashSet::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let bundles: HashSet<PathBuf> = text.lines().filter_map(app_bundle_of).collect();
    bundles.iter().filter_map(|b| bundle_id(b)).collect()
}

/// `/A/X.app/Contents/MacOS/x` ⇒ `/A/X.app` (the innermost app containing the executable).
fn app_bundle_of(exe: &str) -> Option<PathBuf> {
    let i = exe.rfind(".app/Contents/MacOS/")?;
    Some(PathBuf::from(&exe[..i + 4]))
}

fn bundle_id(bundle: &Path) -> Option<String> {
    let v = plist::Value::from_file(bundle.join("Contents/Info.plist")).ok()?;
    v.as_dictionary()?
        .get("CFBundleIdentifier")?
        .as_string()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_bundle_is_the_innermost_app() {
        assert_eq!(
            app_bundle_of("/Applications/A.app/Contents/Frameworks/H.app/Contents/MacOS/H"),
            Some(PathBuf::from(
                "/Applications/A.app/Contents/Frameworks/H.app"
            ))
        );
        assert_eq!(app_bundle_of("/usr/sbin/cfprefsd"), None);
    }

    #[test]
    fn finds_a_system_tool_and_rejects_nonsense() {
        assert!(tool_path("sh").is_some());
        assert!(is_tool_missing("definitely-not-a-tool"));
    }

    #[test]
    fn running_finder_maps_to_its_bundle_id() {
        // Finder runs in every GUI login session; a headless box has nothing to check.
        let finder_running = Path::new("/System/Library/CoreServices/Finder.app").exists()
            && Command::new("pgrep")
                .args(["-x", "Finder"])
                .stdout(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
        if finder_running {
            assert!(running_app_bundle_ids().contains("com.apple.finder"));
        }
    }
}
