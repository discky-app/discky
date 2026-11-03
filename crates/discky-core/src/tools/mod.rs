//! External tools: where a cleanup command's binary lives, and which apps are running.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Where macOS keeps `lsappinfo`; not on a bare `$PATH`.
const LSAPPINFO: &str = "/usr/bin/lsappinfo";
const LSAPPINFO_TIMEOUT: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(20);

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

/// Run `program args…` (stdin null, stderr discarded) and return its stdout when it exits
/// 0 within `timeout`. On timeout the child is killed and reaped; a spawn failure, a
/// non-zero exit or a timeout all give `None`. Stdout is drained on a helper thread, so a
/// chatty child (e.g. `pkgutil --files` with thousands of lines) never blocks on a full pipe.
pub fn run_capture(program: &Path, args: &[&str], timeout: Duration) -> Option<String> {
    run_capture_env(program, args, &[], timeout)
}

/// [`run_capture`] with extra environment variables set on the child only.
pub fn run_capture_env(
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let ok = stdout.read_to_end(&mut buf).is_ok();
        let _ = tx.send(ok.then_some(buf));
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    // A grandchild could keep the pipe open after the child exits: wait no longer than the
    // remaining budget (at least one poll interval).
    let left = deadline.saturating_duration_since(Instant::now()).max(POLL);
    let bytes = rx.recv_timeout(left).ok()??;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Bundle ids of running apps. Uses `lsappinfo list` (entries of type `Foreground` or
/// `UIElement`) when `/usr/bin/lsappinfo` exists and answers within 2 s; otherwise one
/// `ps -axo comm=` call, each `/…/X.app/Contents/MacOS/…` executable mapped to
/// `X.app/Contents/Info.plist`'s `CFBundleIdentifier`. Nothing is cached; on any failure
/// the set is just smaller.
pub fn running_app_bundle_ids() -> HashSet<String> {
    let lsappinfo = Path::new(LSAPPINFO);
    if is_executable(lsappinfo)
        && let Some(text) = run_capture(lsappinfo, &["list"], LSAPPINFO_TIMEOUT)
    {
        return parse_lsappinfo_list(&text);
    }
    running_via_ps()
}

/// Bundle ids from `lsappinfo list` output. Each entry starts with ` N) "name" ASN:…` and
/// carries `bundleID="…"` (or `bundleID=[ NULL ]`) and a `type="…"` field on later lines.
pub(crate) fn parse_lsappinfo_list(text: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    let mut bundle: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut flush = |bundle: &mut Option<String>, kind: &mut Option<String>| {
        if let (Some(b), Some(k)) = (bundle.take(), kind.take())
            && (k == "Foreground" || k == "UIElement")
        {
            ids.insert(b);
        }
        *bundle = None;
        *kind = None;
    };
    for line in text.lines() {
        let t = line.trim_start();
        if is_entry_header(t) {
            flush(&mut bundle, &mut kind);
        }
        if let Some(v) = quoted_field(t, "bundleID=") {
            bundle = Some(v.to_string());
        }
        if let Some(v) = quoted_field(t, "type=") {
            kind = Some(v.to_string());
        }
    }
    flush(&mut bundle, &mut kind);
    ids
}

/// ` 12) "Name" ASN:…`: digits followed by `) `.
fn is_entry_header(trimmed: &str) -> bool {
    let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && trimmed[digits..].starts_with(") ")
}

/// The `"…"` value right after `key` (at a word boundary) in `line`, if quoted.
fn quoted_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = line[from..].find(key) {
        let at = from + i;
        let boundary = at == 0 || line.as_bytes()[at - 1].is_ascii_whitespace();
        let rest = &line[at + key.len()..];
        if boundary && let Some(rest) = rest.strip_prefix('"') {
            return rest.find('"').map(|end| &rest[..end]);
        }
        from = at + key.len();
    }
    None
}

fn running_via_ps() -> HashSet<String> {
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
    fn lsappinfo_list_keeps_foreground_and_ui_element_apps() {
        let text = r#" 1) "loginwindow" ASN:0x0-0x3003: 
    bundleID="com.apple.loginwindow"
    bundle path="/System/Library/CoreServices/loginwindow.app"
    pid = 406 type="UIElement" flavor=3 Version="3085.2.2" fileType="APPL" creator="lgnw" Arch=ARM64 
 2) "universalaccessd" ASN:0x0-0x8008: 
    bundleID=[ NULL ] 
    bundle path="/usr/sbin/universalaccessd"
    pid = 951 !signalled type="BackgroundOnly" flavor=3 Version=[ NULL ]  fileType="????" creator="????" Arch=ARM64 
 3) "Slack" ASN:0x0-0x68068: 
    bundleID="com.tinyspeck.slackmacgap"
    bundle path="/Applications/Slack.app"
    pid = 1200 type="Foreground" flavor=3 Version="4.46" fileType="APPL" Arch=ARM64 
 4) "Helper" ASN:0x0-0x99099: 
    bundleID="com.example.helper"
    pid = 1300 type="BackgroundOnly" flavor=3 
 5) "NoType" ASN:0x0-0x1: 
    bundleID="com.example.notype"
"#;
        let ids = parse_lsappinfo_list(text);
        let mut ids: Vec<_> = ids.into_iter().collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["com.apple.loginwindow", "com.tinyspeck.slackmacgap"]
        );
    }

    #[test]
    fn run_capture_returns_stdout_only_on_success() {
        let sh = Path::new("/bin/sh");
        let t = Duration::from_secs(5);
        assert_eq!(
            run_capture(sh, &["-c", "echo hi"], t).as_deref(),
            Some("hi\n")
        );
        assert_eq!(run_capture(sh, &["-c", "echo x; exit 3"], t), None);
        assert_eq!(run_capture(Path::new("/definitely/not/here"), &[], t), None);
        // Large output does not deadlock on the pipe.
        let big = run_capture(sh, &["-c", "yes | head -n 200000"], t).unwrap();
        assert_eq!(big.lines().count(), 200000);
        let env = run_capture_env(sh, &["-c", "echo $DISCKY_T"], &[("DISCKY_T", "v")], t);
        assert_eq!(env.as_deref(), Some("v\n"));
    }

    #[test]
    fn run_capture_kills_on_timeout() {
        let start = Instant::now();
        let out = run_capture(Path::new("/bin/sleep"), &["5"], Duration::from_millis(100));
        assert_eq!(out, None);
        assert!(start.elapsed() < Duration::from_secs(2));
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
