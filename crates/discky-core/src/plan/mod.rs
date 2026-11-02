//! Removal plans: what would be done to remove a set of findings, with no side effects.
//!
//! [`plan_removal`] turns findings into ordered [`Step`]s; the executor (Task 10) runs
//! them and uses each step's [`Fingerprint`]s to refuse when the target changed since
//! planning.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use xxhash_rust::xxh3::xxh3_64;

use crate::config::{Config, RemovalMode};
use crate::findings::{Finding, FindingId, Removal, ollama_url};
use crate::tools;

pub mod execute;

/// 16 hex chars of `xxh3_64` over `created_at`, a per-process counter and the planned
/// finding ids. The counter keeps two plans of the same findings made in the same second
/// apart (e.g. before and after a removal-mode change), so `Engine::get_plan` never
/// returns the older one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct StepFlags: u8 {
        /// Needs the user: a `Quit` step, or a step with a path whose nearest existing
        /// ancestor (the path itself when it exists, and its parent directory) is not
        /// writable by the current uid (`access(W_OK)`) or is owned by another uid — i.e.
        /// removing it would need an admin prompt. See [`needs_admin`].
        const INTERACTIVE = 1;
        /// Deleted outright instead of moved to the Trash.
        const PERMANENT = 1 << 1;
        /// The command's tool is not installed; the step carries an install hint.
        const TOOL_MISSING = 1 << 2;
    }
}

const FLAG_NAMES: [(StepFlags, &str); 3] = [
    (StepFlags::INTERACTIVE, "interactive"),
    (StepFlags::PERMANENT, "permanent"),
    (StepFlags::TOOL_MISSING, "tool_missing"),
];

impl StepFlags {
    /// Lowercase names of the set flags, e.g. `["interactive", "permanent"]`.
    pub fn names(self) -> Vec<&'static str> {
        FLAG_NAMES
            .iter()
            .filter(|(f, _)| self.contains(*f))
            .map(|&(_, n)| n)
            .collect()
    }
}

impl Serialize for StepFlags {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.names().serialize(s)
    }
}

impl<'de> Deserialize<'de> for StepFlags {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let names = Vec::<String>::deserialize(d)?;
        names.iter().try_fold(StepFlags::empty(), |acc, n| {
            FLAG_NAMES
                .iter()
                .find(|(_, name)| name == n)
                .map(|&(f, _)| acc | f)
                .ok_or_else(|| serde::de::Error::custom(format!("unknown step flag `{n}`")))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Quit {
        bundle_id: String,
    },
    Trash {
        paths: Vec<PathBuf>,
    },
    Remove {
        paths: Vec<PathBuf>,
    },
    Command {
        argv: Vec<String>,
        cwd: Option<PathBuf>,
    },
    OllamaDelete {
        url: String,
        model: String,
    },
}

/// A path's state at planning time (`lstat`; a missing path is all zeros).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub path: PathBuf,
    pub exists: bool,
    /// Unix seconds.
    pub mtime: i64,
    /// `st_blocks * 512`.
    pub allocated: u64,
}

impl Fingerprint {
    /// `lstat` of `path`. A missing path is `exists = false, mtime = 0, allocated = 0`.
    /// Any other error (EACCES, ELOOP…) means the state is unknown: `exists = true,
    /// mtime = -1, allocated = 0`, which compares equal to itself, so a later re-take
    /// under the same error is not stale — and is never mistaken for "already gone".
    pub fn take(path: &Path) -> Fingerprint {
        use std::os::unix::fs::MetadataExt;
        let (exists, mtime, allocated) = match std::fs::symlink_metadata(path) {
            Ok(m) => (true, m.mtime(), m.blocks() * 512),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, 0, 0),
            Err(_) => (true, -1, 0),
        };
        Fingerprint {
            path: path.to_path_buf(),
            exists,
            mtime,
            allocated,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Position in [`Plan::steps`].
    pub index: usize,
    pub finding: FindingId,
    /// Short English sentence, e.g. "Move ~/Library/Caches/pnpm to the Trash".
    pub description: String,
    pub kind: StepKind,
    /// Bytes credited when the step succeeds; `None` for `Quit` and for commands whose
    /// effect cannot be measured here (see `freed_note`).
    pub freed: Option<u64>,
    pub freed_note: Option<String>,
    pub flags: StepFlags,
    pub warnings: Vec<String>,
    pub fingerprints: Vec<Fingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: PlanId,
    pub created_at: i64,
    /// `Quit` steps first, then commands and Ollama deletes, then trash/remove; input
    /// order within each group.
    pub steps: Vec<Step>,
    /// Sum of every step's `freed`.
    pub total_freed: u64,
    /// Findings not planned, with the reason.
    pub skipped: Vec<(FindingId, String)>,
}

/// Whether removing `path` would need an admin prompt: the path itself (when it exists,
/// by `lstat`) or the nearest existing ancestor of its parent — resolved through
/// symlinks, so `~/link -> /Library/Logs` counts as `/Library/Logs`; a dangling link is
/// skipped — is not writable by us or is owned by another uid. Temp dirs under
/// `/var/folders` are ours; `/Library/Logs/X` is not.
pub fn needs_admin(path: &Path) -> bool {
    if std::fs::symlink_metadata(path).is_ok_and(|m| !writable_and_ours(path, &m)) {
        return true;
    }
    let ancestor = path.parent().and_then(|p| {
        p.ancestors()
            .find_map(|a| std::fs::metadata(a).ok().map(|m| (a, m)))
    });
    ancestor.is_some_and(|(a, m)| !writable_and_ours(a, &m))
}

/// Whether `m` (the metadata of `path`) is owned by us and `path` is `access(W_OK)`.
fn writable_and_ours(path: &Path, m: &std::fs::Metadata) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `getuid` has no preconditions.
    if m.uid() != unsafe { libc::getuid() } {
        return false;
    }
    if m.file_type().is_symlink() {
        // Only for the path itself (lstat): the link is ours; `access` would follow it.
        return true;
    }
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// `path` with a leading `$HOME` shown as `~`.
fn display(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty())
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return if rest.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rest.display())
        };
    }
    path.display().to_string()
}

fn display_paths(paths: &[PathBuf]) -> String {
    match paths {
        [one] => display(one),
        _ => format!("{} items", paths.len()),
    }
}

/// The bundle id of a running app a finding belongs to: the finding's directory name
/// (app caches and containers are named after it). M1 findings never carry
/// `"app-running"`; the uninstaller (M3) sets it.
fn running_bundle_id(f: &Finding) -> Option<String> {
    if !f.flags.iter().any(|fl| fl == "app-running") {
        return None;
    }
    let name = f.path.as_deref()?.file_name()?.to_string_lossy();
    Some(name.into_owned())
}

fn step(f: &Finding, description: String, kind: StepKind) -> Step {
    Step {
        index: 0,
        finding: f.id.clone(),
        description,
        kind,
        freed: Some(f.freed_if_deleted),
        freed_note: None,
        flags: StepFlags::empty(),
        warnings: Vec::new(),
        fingerprints: Vec::new(),
    }
}

/// The finding's main step, or the reason it is skipped.
fn removal_step(f: &Finding, cfg: &Config) -> Result<Step, String> {
    match &f.removal {
        Removal::None => Err("Marked do-not-touch".to_string()),
        Removal::Trash { paths } if paths.is_empty() => Err("Nothing to remove".to_string()),
        Removal::Trash { paths } => {
            let shown = display_paths(paths);
            let mut s = match cfg.removal.mode {
                RemovalMode::Trash => step(
                    f,
                    format!("Move {shown} to the Trash"),
                    StepKind::Trash {
                        paths: paths.clone(),
                    },
                ),
                RemovalMode::Permanent => {
                    let mut s = step(
                        f,
                        format!("Delete {shown} permanently"),
                        StepKind::Remove {
                            paths: paths.clone(),
                        },
                    );
                    s.flags |= StepFlags::PERMANENT;
                    s
                }
            };
            if paths.iter().any(|p| needs_admin(p)) {
                s.flags |= StepFlags::INTERACTIVE;
            }
            s.fingerprints = paths.iter().map(|p| Fingerprint::take(p)).collect();
            Ok(s)
        }
        Removal::Command {
            tool,
            argv,
            cwd,
            install_hint,
            freed_note,
        } => {
            let mut description = format!("Run `{}`", argv.join(" "));
            if let Some(cwd) = cwd {
                description.push_str(&format!(" in {}", display(cwd)));
            }
            // Resolve the program so a bare GUI `PATH` still finds Homebrew tools.
            let mut resolved = argv.clone();
            if let Some(first) = resolved.first_mut()
                && let Some(p) = tools::tool_path(first)
            {
                *first = p.to_string_lossy().into_owned();
            }
            let mut s = step(
                f,
                description,
                StepKind::Command {
                    argv: resolved,
                    cwd: cwd.clone(),
                },
            );
            if tools::is_tool_missing(tool) {
                s.flags |= StepFlags::TOOL_MISSING;
                let mut w = format!("{tool} not found.");
                if let Some(hint) = install_hint {
                    w.push(' ');
                    w.push_str(hint);
                }
                s.warnings.push(w);
            }
            if freed_note.is_some() {
                s.freed = None;
                s.freed_note = freed_note.clone();
            }
            s.fingerprints = f
                .path
                .iter()
                .chain(cwd)
                .map(|p| Fingerprint::take(p))
                .collect();
            Ok(s)
        }
        Removal::OllamaDelete { model } => Ok(step(
            f,
            format!("Delete ollama model {model}"),
            StepKind::OllamaDelete {
                url: ollama_url(),
                model: model.clone(),
            },
        )),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Plan the removal of `findings` (no side effects beyond `lstat`/`access` and tool
/// lookup). See [`Plan::steps`] for the order and [`StepFlags`] for the flags.
pub fn plan_removal(findings: &[&Finding], cfg: &Config) -> Plan {
    let created_at = now_secs();
    let mut quits = Vec::new();
    let mut commands = Vec::new();
    let mut trashes = Vec::new();
    let mut skipped = Vec::new();
    let mut quitting = HashSet::new();
    for f in findings {
        let main = match removal_step(f, cfg) {
            Ok(s) => s,
            Err(reason) => {
                skipped.push((f.id.clone(), reason));
                continue;
            }
        };
        if let Some(bundle_id) = running_bundle_id(f)
            && quitting.insert(bundle_id.clone())
        {
            let mut q = step(
                f,
                format!("Quit {} ({bundle_id})", f.title),
                StepKind::Quit { bundle_id },
            );
            q.freed = None;
            q.flags |= StepFlags::INTERACTIVE;
            quits.push(q);
        }
        match main.kind {
            StepKind::Command { .. } | StepKind::OllamaDelete { .. } => commands.push(main),
            _ => trashes.push(main),
        }
    }
    let mut steps: Vec<Step> = quits.into_iter().chain(commands).chain(trashes).collect();
    for (i, s) in steps.iter_mut().enumerate() {
        s.index = i;
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ids: Vec<&str> = findings.iter().map(|f| f.id.0.as_str()).collect();
    let id = PlanId(format!(
        "{:016x}",
        xxh3_64(format!("{created_at}:{n}:{}", ids.join(",")).as_bytes())
    ));
    let total_freed = steps.iter().filter_map(|s| s.freed).sum();
    Plan {
        id,
        created_at,
        steps,
        total_freed,
        skipped,
    }
}

impl Plan {
    /// Flat JSON for the MCP server and the GUI: each step's `kind` is its name and the
    /// kind's fields (`argv`, `cwd`, `paths`, `bundle_id`, `url`, `model`) sit beside it.
    pub fn to_json(&self) -> Value {
        let steps: Vec<Value> = self
            .steps
            .iter()
            .map(|s| {
                let mut v = json!({
                    "index": s.index,
                    "finding": s.finding.0,
                    "description": s.description,
                    "freed": s.freed,
                    "freed_note": s.freed_note,
                    "flags": s.flags.names(),
                    "warnings": s.warnings,
                });
                let o = v.as_object_mut().expect("object literal");
                let (kind, extra) = match &s.kind {
                    StepKind::Quit { bundle_id } => ("quit", json!({ "bundle_id": bundle_id })),
                    StepKind::Trash { paths } => ("trash", json!({ "paths": paths })),
                    StepKind::Remove { paths } => ("remove", json!({ "paths": paths })),
                    StepKind::Command { argv, cwd } => {
                        ("command", json!({ "argv": argv, "cwd": cwd }))
                    }
                    StepKind::OllamaDelete { url, model } => {
                        ("ollama_delete", json!({ "url": url, "model": model }))
                    }
                };
                o.insert("kind".into(), kind.into());
                if let Value::Object(extra) = extra {
                    o.extend(extra);
                }
                v
            })
            .collect();
        let skipped: Vec<Value> = self
            .skipped
            .iter()
            .map(|(id, reason)| json!({ "finding": id.0, "reason": reason }))
            .collect();
        json!({
            "id": self.id.0,
            "created_at": self.created_at,
            "total_freed": self.total_freed,
            "steps": steps,
            "skipped": skipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn plans_of_the_same_findings_in_the_same_second_get_distinct_ids() {
        let cfg = Config::default();
        let a = plan_removal(&[], &cfg);
        let b = plan_removal(&[], &cfg);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn fingerprint_of_unreadable_path_is_unknown_not_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("f"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let fp = Fingerprint::take(&locked.join("f"));
        let again = Fingerprint::take(&locked.join("f"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        // root can stat through mode 000; then the file is simply visible.
        if unsafe { libc::geteuid() } != 0 {
            assert!(fp.exists);
            assert_eq!((fp.mtime, fp.allocated), (-1, 0));
            assert_eq!(fp, again);
        }
        let gone = Fingerprint::take(&tmp.path().join("nope"));
        assert_eq!((gone.exists, gone.mtime, gone.allocated), (false, 0, 0));
    }
}
