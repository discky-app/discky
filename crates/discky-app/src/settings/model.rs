//! Pure settings model: MCP client snippets, binary detection, threshold parsing, mise info
//! and links. No GPUI imports.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use discky_core::tools::tool_path;

// ---------------------------------------------------------------- clients

/// An agent client the Settings screen can show a connection snippet for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Client {
    ClaudeCode,
    ClaudeDesktop,
    Codex,
    Cursor,
    Json,
}

/// All clients, in tab order.
pub const CLIENTS: [Client; 5] = [
    Client::ClaudeCode,
    Client::ClaudeDesktop,
    Client::Codex,
    Client::Cursor,
    Client::Json,
];

impl Client {
    /// Short tab label.
    pub fn label(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::ClaudeDesktop => "Claude Desktop",
            Client::Codex => "Codex",
            Client::Cursor => "Cursor",
            Client::Json => "JSON",
        }
    }

    /// The copyable connection snippet (README "Connect to your agent") for `bin`.
    pub fn snippet(self, bin: &Path) -> String {
        let bin_str = bin.display().to_string();
        match self {
            Client::ClaudeCode => format!("claude mcp add discky -- {bin_str}"),
            Client::Codex => format!("[mcp_servers.discky]\ncommand = \"{bin_str}\""),
            Client::ClaudeDesktop | Client::Cursor | Client::Json => {
                let v = serde_json::json!({"mcpServers": {"discky": {"command": bin_str}}});
                serde_json::to_string_pretty(&v).unwrap_or_default()
            }
        }
    }
}

// ----------------------------------------------------------------- binary

/// Places `discky-mcp` may live, in preference order.
pub fn mcp_binary_candidates(home: &Path, exe: Option<&Path>) -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/opt/homebrew/bin/discky-mcp"),
        home.join(".cargo/bin/discky-mcp"),
    ];
    if let Some(dir) = exe.and_then(Path::parent) {
        v.push(dir.join("discky-mcp"));
    }
    v
}

/// The first existing `discky-mcp` candidate.
pub fn find_mcp_binary(home: &Path, exe: Option<&Path>) -> Option<PathBuf> {
    first_existing(&mcp_binary_candidates(home, exe))
}

fn first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.exists()).cloned()
}

// ------------------------------------------------------------------ tools

/// MCP tools shown in Settings: (name, one-line purpose), from the server's tool descriptions.
pub const MCP_TOOLS: [(&str, &str); 10] = [
    (
        "disk_overview",
        "Disk usage summary from the last scan: volume size and free space, bytes per category, bytes safe to free, and whether the snapshot is stale.",
    ),
    (
        "scan",
        "Starts a scan of the configured roots (or `roots`) in the background and returns its id; with `wait_seconds` it waits for the result.",
    ),
    (
        "scan_status",
        "Status of a scan started with `scan`: running (with progress), done, failed, cancelled or unknown.",
    ),
    (
        "findings",
        "Removable things found by the last scan, largest first, with size, safety label and removal method; filter by category, label, size or age.",
    ),
    (
        "tree",
        "The largest children of a directory in the last snapshot, with allocated and freed-if-deleted bytes.",
    ),
    (
        "search",
        "Search the last snapshot for files and directories by name glob, size, age, kind or parent path, largest first.",
    ),
    (
        "inspect",
        "Everything known about a finding id, an absolute path or an app name: the finding, its rule explanation, size and largest children.",
    ),
    (
        "plan_removal",
        "Plans the removal of the given findings and returns the ordered steps and the bytes they free.",
    ),
    (
        "execute_plan",
        "DELETES files: runs a plan from `plan_removal` (moving items to the Trash or deleting them, per the user's settings).",
    ),
    (
        "history",
        "Removals Discky has run, newest first, and the items it moved to the Trash that are still there.",
    ),
];

// ------------------------------------------------------------- thresholds

/// Parses a whole number of megabytes (decimal, 1 MB = 1 000 000 bytes); rejects 0 and garbage.
pub fn parse_mb(s: &str) -> Option<u64> {
    parse_positive(s)?.checked_mul(1_000_000)
}

/// Parses a positive number of days.
pub fn parse_days(s: &str) -> Option<u32> {
    parse_positive(s)?.try_into().ok()
}

fn parse_positive(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|&n| n > 0)
}

// ------------------------------------------------------------------- mise

/// Detected mise installation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MiseInfo {
    /// First line of `mise --version`.
    pub version: String,
    /// `~/.local/share/mise`, when that directory exists.
    pub data_dir: Option<PathBuf>,
}

const MISE_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs `mise --version` (at most 2 s); `None` when mise is missing or fails.
pub fn mise_info(home: &Path) -> Option<MiseInfo> {
    let mut child = Command::new(tool_path("mise")?)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + MISE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            _ => return None,
        }
    }
    let mut out = String::new();
    io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    let version = out.lines().next()?.trim().to_string();
    if version.is_empty() {
        return None;
    }
    let dir = home.join(".local/share/mise");
    Some(MiseInfo {
        version,
        data_dir: dir.is_dir().then_some(dir),
    })
}

// ------------------------------------------------------------------ links

/// Project repository (placeholder until the repo is public).
pub const REPO_URL: &str = "https://github.com/OWNER/discky";
/// About shows a Donate row only when this is `Some`.
pub const DONATE_URL: Option<&str> = None;
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn snippets_substitute_binary_path() {
        let bin = Path::new("/opt/homebrew/bin/discky-mcp");
        for c in CLIENTS {
            assert!(
                c.snippet(bin).contains("/opt/homebrew/bin/discky-mcp"),
                "{c:?}"
            );
        }
        let v: serde_json::Value = serde_json::from_str(&Client::Json.snippet(bin)).unwrap();
        assert_eq!(
            v["mcpServers"]["discky"]["command"],
            "/opt/homebrew/bin/discky-mcp"
        );
    }

    #[test]
    fn candidates_order_and_first_existing() {
        let home = tempfile::tempdir().unwrap();
        let exe_dir = tempfile::tempdir().unwrap();
        let exe = exe_dir.path().join("discky-app");
        let c = mcp_binary_candidates(home.path(), Some(&exe));
        assert_eq!(c[0], PathBuf::from("/opt/homebrew/bin/discky-mcp"));
        assert_eq!(c[1], home.path().join(".cargo/bin/discky-mcp"));
        assert_eq!(c[2], exe_dir.path().join("discky-mcp"));
    }

    #[test]
    fn first_existing_picks_first_present_candidate() {
        let d = tempfile::tempdir().unwrap();
        let brew = d.path().join("brew/discky-mcp");
        let cargo = d.path().join("cargo/discky-mcp");
        let exe = d.path().join("exe/discky-mcp");
        let list = [brew.clone(), cargo.clone(), exe.clone()];
        assert_eq!(first_existing(&list), None);
        for p in [&cargo, &exe] {
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, "").unwrap();
        }
        assert_eq!(first_existing(&list), Some(cargo.clone()));
        fs::remove_file(&cargo).unwrap();
        assert_eq!(first_existing(&list), Some(exe));
    }

    #[test]
    fn parse_thresholds_reject_zero_and_garbage() {
        assert_eq!(parse_mb("500"), Some(500_000_000));
        assert_eq!(parse_mb(" 1 \n"), Some(1_000_000));
        for s in ["", " ", "0", "-5", "1.5", "abc", "10MB"] {
            assert_eq!(parse_mb(s), None, "{s:?}");
        }
        assert_eq!(parse_days("30"), Some(30));
        for s in ["", "0", "x", "-1"] {
            assert_eq!(parse_days(s), None, "{s:?}");
        }
    }
}
