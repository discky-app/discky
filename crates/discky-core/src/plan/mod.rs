//! Removal plans: what would be done to remove a set of findings, with no side effects.
//!
//! [`plan_items`] (and its shorthand [`plan_removal`]) turns findings — and the selected
//! [`crate::findings::Component`]s of each — into ordered [`Step`]s; the executor runs
//! them and uses each step's [`Fingerprint`]s to refuse when the target changed since
//! planning.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use xxhash_rust::xxh3::xxh3_64;

use crate::config::{Config, RemovalMode};
use crate::findings::{ComponentKind, ComponentRemoval, Finding, FindingId, Removal, ollama_url};
use crate::paths;
use crate::tools;

mod app;
pub mod execute;

pub use app::{GLOBAL_MISE_VERSION, PlanTools, ZapInfo};

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
        /// Extra environment for the child (e.g. `HOMEBREW_NO_AUTO_UPDATE=1`); never set
        /// on admin (`INTERACTIVE`) commands.
        #[serde(default)]
        env: Vec<(String, String)>,
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

/// One finding to plan and which of its components to act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanItem {
    /// The finding's id ([`FindingId`] as a string).
    pub id: String,
    /// Component indices to act on; `None` = every `default_on` component.
    pub components: Option<Vec<usize>>,
}

impl PlanItem {
    /// The finding `id` with its default components.
    pub fn defaults(id: &FindingId) -> PlanItem {
        PlanItem {
            id: id.0.clone(),
            components: None,
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
    /// Index into the finding's `components` this step acts on, when it acts on one.
    #[serde(default)]
    pub component: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: PlanId,
    pub created_at: i64,
    /// In five groups, input order within each: `Quit`s; vendor and source commands
    /// (own uninstaller, `brew`, `launchctl bootout`, `mise uninstall`, rule commands,
    /// Ollama deletes); trash/remove; `defaults delete`; `pkgutil --forget`.
    pub steps: Vec<Step>,
    /// Sum of every step's `freed`.
    pub total_freed: u64,
    /// Findings not planned, with the reason (e.g. do-not-touch, or every path already
    /// gone at planning time).
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
/// (app caches and containers are named after it), or an app removal's own bundle id.
/// M1 findings never carry `"app-running"`; the uninstaller (M3) sets it.
fn running_bundle_id(f: &Finding) -> Option<String> {
    if !f.flags.iter().any(|fl| fl == "app-running") {
        return None;
    }
    if let Removal::App {
        bundle_id: Some(id),
        ..
    } = &f.removal
    {
        return Some(id.clone());
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
        component: None,
    }
}

/// A step trashing (or, in permanent mode, deleting) `paths`, `INTERACTIVE` when any of
/// them needs an administrator, with every path fingerprinted.
fn path_step(f: &Finding, paths: &[PathBuf], cfg: &Config) -> Step {
    let shown = display_paths(paths);
    let mut s = match cfg.removal.mode {
        RemovalMode::Trash => step(
            f,
            format!("Move {shown} to the Trash"),
            StepKind::Trash {
                paths: paths.to_vec(),
            },
        ),
        RemovalMode::Permanent => {
            let mut s = step(
                f,
                format!("Delete {shown} permanently"),
                StepKind::Remove {
                    paths: paths.to_vec(),
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
    s
}

/// Index of the finding's `AppBundle` component, if it has one.
fn bundle_component(f: &Finding) -> Option<usize> {
    f.components
        .iter()
        .position(|c| c.kind == ComponentKind::AppBundle)
}

/// The finding's main step (`None` when the selection leaves it out), or the reason the
/// finding is skipped.
fn removal_step(f: &Finding, cfg: &Config) -> Result<Option<Step>, String> {
    match &f.removal {
        Removal::None => Err("Marked do-not-touch".to_string()),
        Removal::Trash { paths } if paths.is_empty() => Err("Nothing to remove".to_string()),
        Removal::Trash { paths } => Ok(Some(path_step(f, paths, cfg))),
        // Composed by `app::plan_finding`, which never asks for a main step of these.
        Removal::App { .. } | Removal::MiseUninstall { .. } => Ok(None),
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
                    env: Vec::new(),
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
            Ok(Some(s))
        }
        Removal::OllamaDelete { model } => Ok(Some(step(
            f,
            format!("Delete ollama model {model}"),
            StepKind::OllamaDelete {
                url: ollama_url(),
                model: model.clone(),
            },
        ))),
    }
}

/// The component indices `item` selects in `f`, in component order, or why it cannot be
/// planned.
fn selected_components(f: &Finding, item: &PlanItem) -> Result<Vec<usize>, String> {
    match &item.components {
        None => Ok((0..f.components.len())
            .filter(|&i| f.components[i].default_on)
            .collect()),
        Some(_) if f.components.is_empty() => Err("Finding has no components".to_string()),
        Some(chosen) => {
            if let Some(bad) = chosen.iter().find(|&&i| i >= f.components.len()) {
                return Err(format!("Unknown component index {bad}"));
            }
            Ok((0..f.components.len())
                .filter(|i| chosen.contains(i))
                .collect())
        }
    }
}

const ALREADY_GONE: &str = "Already gone (rescan to refresh)";
/// Skip reason for an id that is not among the findings (e.g. not in the snapshot).
pub const UNKNOWN_ID: &str = "Unknown finding id (rescan?)";

/// Every path the finding's removal acts on is missing now (by [`Fingerprint::take`], so
/// an unreadable path is never "gone"). Trash removals act on their paths, commands on
/// the finding's path; Ollama models and findings without paths are never gone here.
fn already_gone(f: &Finding) -> bool {
    let paths: Vec<&Path> = match &f.removal {
        Removal::Trash { paths } => paths.iter().map(PathBuf::as_path).collect(),
        Removal::App { bundle, .. } => std::iter::once(bundle.as_path())
            .chain(
                f.components
                    .iter()
                    .filter(|c| c.removal == ComponentRemoval::Trash)
                    .filter_map(|c| c.path.as_deref()),
            )
            .collect(),
        Removal::Command { .. } | Removal::MiseUninstall { .. } => {
            f.path.as_deref().into_iter().collect()
        }
        Removal::OllamaDelete { .. } | Removal::None => Vec::new(),
    };
    !paths.is_empty() && paths.iter().all(|p| !Fingerprint::take(p).exists)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Plan the removal of `findings`, each with its default components: [`plan_items`] with
/// `components: None` for every finding.
pub fn plan_removal(findings: &[&Finding], cfg: &Config) -> Plan {
    let items: Vec<PlanItem> = findings.iter().map(|f| PlanItem::defaults(&f.id)).collect();
    plan_items(&items, findings, cfg)
}

/// Plan `items`, looked up by id in `findings` (no side effects beyond `lstat`/`access`
/// and read-only lookups: tool paths, loaded launchd jobs, cask and package records, and
/// the running apps when a running cask app is planned — see [`PlanTools::detect`]).
/// [`plan_items_with_tools`] with the real lookups.
pub fn plan_items(items: &[PlanItem], findings: &[&Finding], cfg: &Config) -> Plan {
    let want_running = items.iter().any(|item| {
        findings
            .iter()
            .any(|f| f.id.0 == item.id && app::wants_running(f))
    });
    plan_items_with_tools(items, findings, cfg, &PlanTools::detect(want_running))
}

/// Which group of [`Plan::steps`] a step goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Quit,
    /// Own uninstaller, `brew`, `launchctl bootout`, `mise uninstall`, rule commands,
    /// Ollama deletes.
    Vendor,
    Trash,
    Defaults,
    Forget,
}

impl Bucket {
    /// The group of a generic step by its kind.
    fn of(s: &Step) -> Bucket {
        match s.kind {
            StepKind::Quit { .. } => Bucket::Quit,
            StepKind::Command { .. } | StepKind::OllamaDelete { .. } => Bucket::Vendor,
            StepKind::Trash { .. } | StepKind::Remove { .. } => Bucket::Trash,
        }
    }
}

/// [`plan_items`] with the given `tools`. An item whose id is not among `findings`, whose
/// selection names a component the finding does not have, or that selects nothing is
/// listed in [`Plan::skipped`]. See [`Plan::steps`] for the order and [`StepFlags`] for
/// the flags.
pub fn plan_items_with_tools(
    items: &[PlanItem],
    findings: &[&Finding],
    cfg: &Config,
    tools: &PlanTools,
) -> Plan {
    let created_at = now_secs();
    let mut buckets: [Vec<Step>; 5] = Default::default();
    let mut skipped = Vec::new();
    let mut quitting = HashSet::new();
    for item in items {
        let Some(f) = findings.iter().find(|f| f.id.0 == item.id) else {
            skipped.push((FindingId(item.id.clone()), UNKNOWN_ID.to_string()));
            continue;
        };
        let planned = selected_components(f, item).and_then(|sel| {
            if app::handles(f) {
                return app::plan_finding(f, &sel, cfg, tools);
            }
            if already_gone(f) {
                return Err(ALREADY_GONE.to_string());
            }
            let mut steps = Vec::new();
            if let Some(bundle_id) = running_bundle_id(f) {
                let mut q = step(
                    f,
                    format!("Quit {} ({bundle_id})", f.title),
                    StepKind::Quit { bundle_id },
                );
                q.freed = None;
                q.flags |= StepFlags::INTERACTIVE;
                steps.push((Bucket::Quit, q));
            }
            match removal_step(f, cfg)? {
                Some(s) => steps.push((Bucket::of(&s), s)),
                None => return Err("Nothing selected".to_string()),
            }
            Ok(steps)
        });
        let planned = match planned {
            Ok(steps) => steps,
            Err(reason) => {
                skipped.push((f.id.clone(), reason));
                continue;
            }
        };
        for (bucket, s) in planned {
            if let StepKind::Quit { bundle_id } = &s.kind
                && !quitting.insert(bundle_id.clone())
            {
                continue;
            }
            buckets[bucket as usize].push(s);
        }
    }
    let mut steps: Vec<Step> = buckets.into_iter().flatten().collect();
    for (i, s) in steps.iter_mut().enumerate() {
        s.index = i;
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
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
    /// kind's fields (`argv`, `cwd`, `env` as an object, `paths`, `bundle_id`, `url`, `model`) sit beside it;
    /// `component` is the finding component index the step acts on, or null.
    pub fn to_json(&self) -> Value {
        let shown =
            |ps: &[PathBuf]| -> Vec<String> { ps.iter().map(|p| paths::display(p)).collect() };
        let steps: Vec<Value> = self
            .steps
            .iter()
            .map(|s| {
                let mut o = Map::new();
                o.insert("index".into(), s.index.into());
                o.insert("finding".into(), s.finding.0.clone().into());
                o.insert("description".into(), s.description.clone().into());
                o.insert("freed".into(), s.freed.into());
                o.insert("freed_note".into(), s.freed_note.clone().into());
                o.insert("flags".into(), s.flags.names().into());
                o.insert("warnings".into(), s.warnings.clone().into());
                o.insert("component".into(), s.component.into());
                let kind = match &s.kind {
                    StepKind::Quit { bundle_id } => {
                        o.insert("bundle_id".into(), bundle_id.clone().into());
                        "quit"
                    }
                    StepKind::Trash { paths } => {
                        o.insert("paths".into(), shown(paths).into());
                        "trash"
                    }
                    StepKind::Remove { paths } => {
                        o.insert("paths".into(), shown(paths).into());
                        "remove"
                    }
                    StepKind::Command { argv, cwd, env } => {
                        o.insert("argv".into(), argv.clone().into());
                        o.insert("cwd".into(), cwd.as_deref().map(paths::display).into());
                        let env: Map<String, Value> = env
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone().into()))
                            .collect();
                        o.insert("env".into(), env.into());
                        "command"
                    }
                    StepKind::OllamaDelete { url, model } => {
                        o.insert("url".into(), url.clone().into());
                        o.insert("model".into(), model.clone().into());
                        "ollama_delete"
                    }
                };
                o.insert("kind".into(), kind.into());
                Value::Object(o)
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
