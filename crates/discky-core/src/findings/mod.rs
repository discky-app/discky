//! Findings: removable things with an honest size, a safety label and a removal method.
//!
//! [`Categorizer::run`] turns an [`Index`] into findings in seven passes — model stores ([`models`]), rule
//! paths/globs, installed apps and leftovers of removed ones ([`apps`]), mise language versions
//! ([`mise`]), per-app `~/Library` folders
//! ([`app_caches`]), project build dirs ([`builds`]), large & old ([`large_old`]). Each pass
//! records the node of every finding it emits in a shared `claimed` set; a node is
//! claimed when it or any ancestor is in that set (see [`is_claimed`]). Passes walk the
//! tree top-down with [`walk_unclaimed`] and never enter a claimed subtree, so nothing
//! is reported twice.

pub mod app_caches;
pub mod apps;
pub mod builds;
pub mod large_old;
pub mod mise;
pub mod models;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::config::Thresholds;
use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeFlags, NodeId};
use crate::rules::{Category, Rule, RuleSet, SafetyLabel};

/// Stable identifier: 16 hex chars of `xxh3_64("{kind}:{key}")`, where `kind` is
/// `"path"`, `"ollama"`, `"hf"`, `"lmstudio"`, `"omlx"` or `"mise"` and `key` the absolute
/// path, model name or `tool@version`. The same thing gets the same id across scans.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub String);

impl FindingId {
    pub fn new(kind: &str, key: &str) -> FindingId {
        FindingId(format!(
            "{:016x}",
            xxh3_64(format!("{kind}:{key}").as_bytes())
        ))
    }

    pub fn for_path(path: &Path) -> FindingId {
        FindingId::new("path", &path.to_string_lossy())
    }
}

/// How a finding is removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Removal {
    Trash {
        paths: Vec<PathBuf>,
    },
    /// The tool's own cleanup command, run in `cwd` when set.
    Command {
        tool: String,
        argv: Vec<String>,
        cwd: Option<PathBuf>,
        install_hint: Option<String>,
        freed_note: Option<String>,
    },
    OllamaDelete {
        model: String,
    },
    /// An installed application: the bundle itself; the finding's [`Component`]s carry
    /// the leftovers chosen alongside it.
    App {
        source: AppSource,
        bundle: PathBuf,
        bundle_id: Option<String>,
    },
    /// One mise-managed tool version, removed with `mise uninstall <tool>@<version>`.
    MiseUninstall {
        tool: String,
        version: String,
    },
    /// Never removed by Discky (`DoNotTouch`); shown so the user knows it was seen.
    None,
}

/// How an application got onto the Mac, which decides how it is uninstalled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppSource {
    /// A Homebrew cask (`token` short, `full_token` with its tap).
    Cask { token: String, full_token: String },
    /// Installed by one or more installer packages (`pkgutil` receipts).
    Pkg { pkg_ids: Vec<String> },
    /// From the Mac App Store.
    AppStore,
    /// Copied into `/Applications` by hand.
    Dragged,
}

/// What a [`Component`] is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    AppBundle,
    ApplicationSupport,
    Caches,
    Preferences,
    Container,
    GroupContainer,
    SavedState,
    HttpStorage,
    WebKit,
    Cookies,
    Logs,
    LaunchAgent,
    LaunchDaemon,
    ApplicationScript,
    PrivilegedHelper,
    Receipt,
    OwnUninstaller,
    /// A project that requests this finding (e.g. a `mise.toml` pinning a version).
    Project,
    Other,
}

/// How a [`Component`] is removed when it is selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentRemoval {
    /// The component's path goes to the Trash.
    Trash,
    /// `defaults delete <domain>` (the plist is not trashed).
    Defaults { domain: String },
    /// `launchctl bootout gui/<uid>/<label>`, or `system/<label>` (admin) when `system`,
    /// then the plist is trashed.
    Bootout { label: String, system: bool },
    /// `pkgutil --forget <pkg_id>` (admin).
    PkgForget { pkg_id: String },
    /// Run the vendor's own uninstaller script at the component's path (`.scpt` with
    /// `osascript`, `.sh` with `sh`); interactive, since it may ask for a password or show UI.
    RunScript,
    /// Shown only (projects, an uninstaller app, shared folders); the planner refuses
    /// one that is selected explicitly.
    None,
}

/// One part of a finding the user can include in or leave out of its removal: an app's
/// bundle and leftovers, or the projects requesting a tool version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub kind: ComponentKind,
    /// E.g. "Application Support", "LaunchDaemon · active", "requested by mise.toml".
    pub title: String,
    pub path: Option<PathBuf>,
    pub allocated: u64,
    pub freed_if_deleted: u64,
    /// Unix seconds.
    pub modified: Option<i64>,
    /// Pre-checked in the inspector, and acted on when no selection is given.
    pub default_on: bool,
    pub removal: ComponentRemoval,
    /// E.g. "needs administrator password", "shared with Google Drive".
    pub note: Option<String>,
    /// Removed by `brew uninstall --zap`; the planner emits no separate step for it. Set for
    /// a cask app's bundle and for leftovers its cask's `zap` stanza names (equal to, or
    /// under, a `trash`/`delete` path; equal to an `rmdir` path).
    #[serde(default)]
    pub covered_by_cask: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub category: Category,
    pub title: String,
    pub subtitle: Option<String>,
    pub path: Option<PathBuf>,
    pub node: Option<NodeId>,
    pub allocated: u64,
    pub logical: u64,
    /// Bytes actually freed: APFS private size, so clones and hard links are not
    /// counted as space that comes back.
    pub freed_if_deleted: u64,
    /// Unix seconds; for a directory the newest mtime inside it.
    pub modified: Option<i64>,
    pub label: SafetyLabel,
    pub rule_id: String,
    pub explain: String,
    pub removal: Removal,
    /// Any of `"sparse"`, `"dataless"`, `"hardlinks"`, `"no_access"`, `"clone_shared"`; app
    /// findings also `"app-running"` and `"zap-shared"` (the cask's zap stanza names a shared
    /// component: the planner must run `brew uninstall --cask <token>` without `--zap` and
    /// trash the non-shared covered components itself).
    pub flags: Vec<String>,
    /// Selectable parts (app bundle, leftovers, requesting projects); empty for most
    /// findings. Indices are what [`crate::plan::PlanItem::components`] refers to.
    #[serde(default)]
    pub components: Vec<Component>,
}

pub struct Categorizer<'a> {
    pub index: &'a Index,
    pub rules: &'a RuleSet,
    pub thresholds: &'a Thresholds,
}

impl Categorizer<'_> {
    /// All findings, largest `freed_if_deleted` first (ties by path), with the home
    /// directory taken from `$HOME`.
    pub fn run(&self) -> Vec<Finding> {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from);
        self.run_with_home(home.as_deref())
    }

    /// [`Categorizer::run`] with an explicit home directory (`~` for the exclusions,
    /// `~/Downloads`, and the large & old pass, which only looks inside it).
    pub fn run_with_home(&self, home: Option<&Path>) -> Vec<Finding> {
        let mut claimed = HashSet::new();
        let mut out = Vec::new();
        if let Some(home) = home {
            out.extend(models::find(
                self.index,
                self.rules,
                home,
                &ollama_url(),
                &mut claimed,
            ));
        }
        out.extend(rule_pass(self.index, self.rules, &mut claimed));
        if let Some(home) = home {
            // Before App caches: leftover groups of removed apps claim their folders.
            if apps::applies(self.index, home) {
                let running = crate::tools::running_app_bundle_ids();
                out.extend(apps::find(self.index, home, &mut claimed, &running));
            }
            // After apps, before App caches: each version claims its install dir.
            let mise_bin = crate::tools::tool_path("mise");
            out.extend(mise::find(
                self.index,
                home,
                mise_bin.as_deref(),
                &mut claimed,
            ));
            out.extend(app_caches::find(self.index, home, &mut claimed));
        }
        out.extend(builds::find(self.index, self.rules, home, &mut claimed));
        out.extend(large_old::find(
            self.index,
            self.thresholds,
            home,
            &mut claimed,
        ));
        sort_findings(&mut out);
        out
    }
}

/// Ollama server address: `$OLLAMA_HOST` (scheme optional), else the local default.
pub(crate) fn ollama_url() -> String {
    match std::env::var("OLLAMA_HOST") {
        Ok(h) if !h.trim().is_empty() => {
            let h = h.trim();
            if h.contains("://") {
                h.to_string()
            } else {
                format!("http://{h}")
            }
        }
        _ => "http://127.0.0.1:11434".to_string(),
    }
}

/// Appended to `explain` when a removal command template could not be resolved.
pub const UNRESOLVED: &str = " (removal command template unresolved)";

/// Whether any argument still holds a `{placeholder}` template.
pub(crate) fn has_placeholder(argv: &[String]) -> bool {
    argv.iter()
        .any(|a| a.find('{').is_some_and(|i| a[i..].contains('}')))
}

/// Largest `freed_if_deleted` first; ties by path (findings without a path last).
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.freed_if_deleted
            .cmp(&a.freed_if_deleted)
            .then_with(|| match (&a.path, &b.path) {
                (Some(x), Some(y)) => x.cmp(y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.id.0.cmp(&b.id.0),
            })
    });
}

/// A finding for node `id` described by `rule`. Sizes come from the node's aggregates
/// (`freed_if_deleted = agg_private`); `removal` is the rule's command (run in `cwd`),
/// else `Trash`, and always `None` for `DoNotTouch`.
pub fn finding_for_node(index: &Index, id: NodeId, rule: &Rule, cwd: Option<PathBuf>) -> Finding {
    let path = index.path(id);
    let removal = if rule.label == SafetyLabel::DoNotTouch {
        Removal::None
    } else if let Some(cmd) = &rule.command {
        Removal::Command {
            tool: cmd.tool.clone(),
            argv: cmd.argv.clone(),
            cwd,
            install_hint: cmd.install_hint.clone(),
            freed_note: cmd.freed_note.clone(),
        }
    } else {
        Removal::Trash {
            paths: vec![path.clone()],
        }
    };
    let mut f = node_finding(index, id, path, rule.category, rule.label, &rule.id);
    f.title = rule.title.clone();
    f.explain = rule.explain.clone();
    f.removal = removal;
    f
}

/// A finding for `id` at `path` with sizes, dates and flags filled in, the node's name as
/// title, `Trash` removal and an empty `explain`; callers adjust the rest.
pub(crate) fn node_finding(
    index: &Index,
    id: NodeId,
    path: PathBuf,
    category: Category,
    label: SafetyLabel,
    rule_id: &str,
) -> Finding {
    let n = index.node(id);
    let is_dir = n.kind == ObjKind::Dir;
    let (allocated, logical, private, modified) = if is_dir {
        (n.agg_allocated, n.agg_logical, n.agg_private, n.max_mtime)
    } else {
        (n.allocated, n.logical, n.private, n.mtime)
    };
    Finding {
        id: FindingId::for_path(&path),
        category,
        title: index.name(id).to_string_lossy().into_owned(),
        subtitle: None,
        flags: flags_for(index, id, &path),
        removal: Removal::Trash {
            paths: vec![path.clone()],
        },
        path: Some(path),
        node: Some(id),
        allocated,
        logical,
        freed_if_deleted: private,
        modified: Some(modified),
        label,
        rule_id: rule_id.to_string(),
        explain: String::new(),
        components: Vec::new(),
    }
}

/// Flags of the node itself; `"no_access"` also when anything below it was unreadable.
/// `"hardlinks"` is set only from the node's own flag (M1).
fn flags_for(index: &Index, id: NodeId, path: &Path) -> Vec<String> {
    let f = index.node(id).flags;
    let mut out = Vec::new();
    for (flag, name) in [
        (NodeFlags::SPARSE, "sparse"),
        (NodeFlags::DATALESS, "dataless"),
        (NodeFlags::HARDLINK_DUP, "hardlinks"),
    ] {
        if f.contains(flag) {
            out.push(name.to_string());
        }
    }
    if f.contains(NodeFlags::NO_ACCESS) || index.errors.iter().any(|e| e.path.starts_with(path)) {
        out.push("no_access".to_string());
    }
    if f.contains(NodeFlags::CLONE_SHARED) {
        out.push("clone_shared".to_string());
    }
    out
}

/// Whether `id` or any of its ancestors is in `claimed`.
pub fn is_claimed(index: &Index, claimed: &HashSet<NodeId>, id: NodeId) -> bool {
    std::iter::successors(Some(id), |&c| index.node(c).parent).any(|c| claimed.contains(&c))
}

/// Depth-first walk over every root, skipping claimed subtrees. `visit(id, path)` returns
/// whether to descend into `id`. The path is built incrementally (no per-node
/// [`Index::path`]), and is only valid during the call.
pub(crate) fn walk_unclaimed(
    index: &Index,
    claimed: &HashSet<NodeId>,
    mut visit: impl FnMut(NodeId, &Path) -> bool,
) {
    for (&root, root_path) in index.roots.iter().zip(&index.root_paths) {
        let mut path = root_path.clone();
        let mut depth = 0usize;
        let mut stack = vec![(root, 0usize)];
        while let Some((id, d)) = stack.pop() {
            if d > 0 {
                while depth >= d {
                    path.pop();
                    depth -= 1;
                }
                path.push(index.name(id));
                depth = d;
            }
            if claimed.contains(&id) {
                continue;
            }
            if visit(id, &path) {
                stack.extend(index.children(id).map(|c| (c, d + 1)));
            }
        }
    }
}

/// Pass 1: `Path`/`Glob` rules. The highest matching node wins and claims its subtree; a
/// `per_child` rule yields one finding per direct child directory instead.
fn rule_pass(index: &Index, rules: &RuleSet, claimed: &mut HashSet<NodeId>) -> Vec<Finding> {
    let mut hits = Vec::new();
    walk_unclaimed(index, claimed, |id, path| match rules.match_path(path) {
        Some(rule) => {
            hits.push((id, rule));
            false
        }
        None => true,
    });
    let mut out = Vec::new();
    for (id, rule) in hits {
        claimed.insert(id);
        if rule.per_child {
            for child in index.children(id) {
                if index.node(child).kind != ObjKind::Dir {
                    continue;
                }
                let mut f = finding_for_node(index, child, rule, None);
                f.title = index.name(child).to_string_lossy().into_owned();
                // A per-child command cannot know the child: never ship a raw template,
                // and never swap in the Trash for the tool the rule asked for.
                if matches!(&f.removal, Removal::Command { argv, .. } if has_placeholder(argv)) {
                    f.removal = Removal::None;
                    f.explain.push_str(UNRESOLVED);
                }
                out.push(f);
            }
        } else {
            out.push(finding_for_node(index, id, rule, None));
        }
    }
    out
}

/// `rel` paths joined onto `home` (empty without a home).
pub(crate) fn home_dirs(home: Option<&Path>, rel: &[&str]) -> Vec<PathBuf> {
    home.map_or_else(Vec::new, |h| rel.iter().map(|r| h.join(r)).collect())
}
