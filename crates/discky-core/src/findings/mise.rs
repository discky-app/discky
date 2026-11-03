//! Language versions installed by mise: one finding per installed tool version, with the
//! projects that request it.
//!
//! All mise data comes from the mise CLI ([`find`] runs `mise ls --json` and
//! `mise ls --all-sources --json`, each bounded to 5 s), never from mise's internal files.
//! `mise ls --json` gives every installed version with at most one (loaded) `source`;
//! `--all-sources` adds a `sources[]` list from every config file mise has tracked, and
//! also lists requested versions that are not installed (`installed: false`), which are
//! dropped. Sizes come from the index node of the version's `install_path`; the alias
//! symlinks next to it (`19`, `lts-iron`, `latest`) are separate nodes and ignored.
//!
//! Version files mise has never loaded (an `.nvmrc` in a project never `cd`-ed into with
//! mise active) are found in the index under the home directory ([`untracked_version_files`])
//! and attached to the installed version they request, so removing a version warns about
//! them too.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use super::{Component, ComponentKind, ComponentRemoval, Finding, FindingId, Removal};
use super::{is_claimed, node_finding, walk_unclaimed};
use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Category, SafetyLabel};

/// Rule id of every mise version finding (the planner recognises the global one by it).
pub const RULE_ID: &str = "mise-version";
/// The global config, relative to home (`$XDG_CONFIG_HOME` is not consulted).
pub const GLOBAL_CONFIG: &str = ".config/mise/config.toml";
/// mise's default data directory, relative to home; [`find`] asks mise only when it exists.
pub const DATA_DIR: &str = ".local/share/mise";
/// Explanation of the global version, which is not removable.
pub const GLOBAL_EXPLAIN: &str = "Global version; change it in ~/.config/mise/config.toml first";
/// Note of a version file mise has not seen.
pub const NOT_TRACKED: &str = "not tracked by mise";
/// Appended to `explain` when the install dir is not in the index.
pub const SIZE_UNKNOWN: &str = "(size unknown: outside scan roots)";

/// Budget of each mise command.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Version files deeper than this below home are not looked for.
const MAX_DEPTH: usize = 6;
/// Bigger version files are skipped.
const MAX_FILE: u64 = 4096;
/// Names of the version files looked for (plus `.mise/config.toml`).
const VERSION_FILES: [&str; 7] = [
    ".nvmrc",
    ".node-version",
    ".ruby-version",
    ".python-version",
    ".tool-versions",
    "mise.toml",
    ".mise.toml",
];

/// One tool version as `mise ls` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseVersion {
    pub tool: String,
    pub version: String,
    pub install_path: PathBuf,
    pub installed: bool,
    pub active: bool,
    /// Config files requesting this version.
    pub sources: Vec<MiseSource>,
}

/// A config file requesting a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseSource {
    /// `"mise.toml"`, `".tool-versions"` or `"idiomatic-version-file"`, as mise reports it.
    pub kind: String,
    pub path: PathBuf,
    /// The request as written (`"3.12"`, `"latest"`); empty when mise gave none.
    pub requested: String,
}

/// Who needs an installed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionStatus {
    /// Requested by the global config: not removable while it is.
    Global,
    /// Requested by config files in this many project directories.
    Pinned(usize),
    /// No config file mise has seen requests it.
    Unreferenced,
}

/// Parse `mise ls --json`: an object of tool → entries, each with a singular `source`
/// (and `requested_version` on the entry). Malformed entries are skipped; anything but a
/// JSON object is an error.
pub fn parse_ls(json: &str) -> Result<Vec<MiseVersion>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("mise ls --json: {e}"))?;
    let tools = v
        .as_object()
        .ok_or_else(|| "mise ls --json: expected an object of tools".to_string())?;
    let mut out = Vec::new();
    for (tool, entries) in tools {
        for e in entries.as_array().into_iter().flatten() {
            if let Some(mv) = parse_entry(tool, e) {
                out.push(mv);
            }
        }
    }
    Ok(out)
}

/// One `mise ls` entry; `None` without a string `version` and `install_path`.
fn parse_entry(tool: &str, e: &Value) -> Option<MiseVersion> {
    let version = e.get("version")?.as_str()?.to_string();
    let install_path = PathBuf::from(e.get("install_path")?.as_str()?);
    let flag = |k: &str| e.get(k).and_then(Value::as_bool).unwrap_or(false);
    let requested = e
        .get("requested_version")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut sources = Vec::new();
    let all = e.get("sources").and_then(Value::as_array);
    for s in e.get("source").into_iter().chain(all.into_iter().flatten()) {
        if let Some(s) = parse_source(s, requested)
            && !sources.iter().any(|x: &MiseSource| x.path == s.path)
        {
            sources.push(s);
        }
    }
    Some(MiseVersion {
        tool: tool.to_string(),
        version,
        install_path,
        installed: flag("installed"),
        active: flag("active"),
        sources,
    })
}

/// A `{type, path, requested_version?}` object; the entry's request when it has none.
fn parse_source(s: &Value, requested: &str) -> Option<MiseSource> {
    Some(MiseSource {
        kind: s.get("type")?.as_str()?.to_string(),
        path: PathBuf::from(s.get("path")?.as_str()?),
        requested: s
            .get("requested_version")
            .and_then(Value::as_str)
            .unwrap_or(requested)
            .to_string(),
    })
}

/// Add the `sources[]` of `mise ls --all-sources --json` to `versions` (matched by tool
/// and version, de-duplicated by path). Versions no source requests are kept; entries
/// with `installed: false` are dropped. Unreadable `all_sources_json` adds nothing.
pub fn merge_sources(mut versions: Vec<MiseVersion>, all_sources_json: &str) -> Vec<MiseVersion> {
    for a in parse_ls(all_sources_json).unwrap_or_default() {
        match versions
            .iter_mut()
            .find(|v| v.tool == a.tool && v.version == a.version)
        {
            Some(v) => {
                for s in a.sources {
                    if !v.sources.iter().any(|x| x.path == s.path) {
                        v.sources.push(s);
                    }
                }
            }
            None if a.installed => versions.push(a),
            None => {}
        }
    }
    versions.retain(|v| v.installed);
    versions
}

/// [`VersionStatus::Global`] when a source is `home/.config/mise/config.toml`; otherwise
/// pinned in as many projects as there are distinct source directories.
pub fn status_of(v: &MiseVersion, home: &Path) -> VersionStatus {
    let global = home.join(GLOBAL_CONFIG);
    if v.sources.iter().any(|s| s.path == global) {
        return VersionStatus::Global;
    }
    let dirs: HashSet<&Path> = v
        .sources
        .iter()
        .map(|s| s.path.parent().unwrap_or(&s.path))
        .collect();
    match dirs.len() {
        0 => VersionStatus::Unreferenced,
        n => VersionStatus::Pinned(n),
    }
}

/// Version files under `home` that are not in `tracked`, as `(file, tool, requested)`
/// (one entry per requested version). Looks in the index, at most 6 levels below home,
/// skipping `~/Library`, `node_modules` and hidden directories (`.git` among them) except
/// `.mise/config.toml`. Files over 4 KiB or unreadable are skipped. `.nvmrc` /
/// `.node-version` request node, `.ruby-version` ruby, `.python-version` python (first
/// non-comment line, leading `v` removed); `.tool-versions` has `tool version` lines;
/// `mise.toml` / `.mise.toml` / `.mise/config.toml` a `[tools]` table.
pub fn untracked_version_files(
    index: &Index,
    home: &Path,
    tracked: &HashSet<PathBuf>,
) -> Vec<(PathBuf, String, String)> {
    let library = home.join("Library");
    let mut files = Vec::new();
    walk_unclaimed(index, &HashSet::new(), |id, path| {
        let Ok(rel) = path.strip_prefix(home) else {
            // Above home: keep going down towards it.
            return home.starts_with(path);
        };
        let depth = rel.components().count();
        if depth > MAX_DEPTH || path == library {
            return false;
        }
        let name = index.name(id).to_string_lossy();
        match index.node(id).kind {
            ObjKind::Dir if depth == 0 => true,
            ObjKind::Dir if name == ".mise" => {
                if let Some(c) = index.children(id).find(|&c| index.name(c) == "config.toml") {
                    files.push((c, path.join("config.toml")));
                }
                false
            }
            ObjKind::Dir => !name.starts_with('.') && name != "node_modules",
            ObjKind::File => {
                if VERSION_FILES.contains(&name.as_ref()) {
                    files.push((id, path.to_path_buf()));
                }
                false
            }
            _ => false,
        }
    });
    let mut out = Vec::new();
    for (id, path) in files {
        let n = index.node(id);
        if n.kind != ObjKind::File || n.logical > MAX_FILE || tracked.contains(&path) {
            continue;
        }
        let Some(text) = read_small(&path) else {
            continue;
        };
        let name = file_label(&path);
        for (tool, req) in parse_version_file(&name, &text) {
            out.push((path.clone(), tool, req));
        }
    }
    out
}

/// The file's contents when it is UTF-8 and at most [`MAX_FILE`] bytes.
fn read_small(path: &Path) -> Option<String> {
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > MAX_FILE {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// The file name, or `.mise/config.toml` for that one.
fn file_label(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let in_mise_dir = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|p| p == ".mise");
    if in_mise_dir {
        format!(".mise/{name}")
    } else {
        name
    }
}

/// `(tool, requested)` pairs of a version file called `name`; empty requests are dropped.
fn parse_version_file(name: &str, text: &str) -> Vec<(String, String)> {
    let first = || {
        text.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .find(|l| !l.is_empty())
            .unwrap_or("")
    };
    let one = |tool: &str, prefix: &str| {
        let r = first();
        let r = r.strip_prefix(prefix).unwrap_or(r);
        vec![(
            tool.to_string(),
            r.strip_prefix('v').unwrap_or(r).to_string(),
        )]
    };
    let pairs = match name {
        ".nvmrc" | ".node-version" => one("node", "node-"),
        ".ruby-version" => one("ruby", "ruby-"),
        ".python-version" => one("python", "python-"),
        ".tool-versions" => text
            .lines()
            .filter_map(|l| {
                let mut w = l.split('#').next().unwrap_or("").split_whitespace();
                Some((w.next()?.to_string(), w.next()?.to_string()))
            })
            .collect(),
        "mise.toml" | ".mise.toml" | ".mise/config.toml" => toml_tools(text),
        _ => Vec::new(),
    };
    pairs.into_iter().filter(|(_, r)| !r.is_empty()).collect()
}

/// Entries of a mise config's `[tools]` table: `name = "ver"`, `name = ["ver", …]` or
/// `name = { version = "ver" }`. Invalid TOML gives nothing.
fn toml_tools(text: &str) -> Vec<(String, String)> {
    let Ok(doc) = toml::from_str::<toml::Table>(text) else {
        return Vec::new();
    };
    let Some(tools) = doc.get("tools").and_then(toml::Value::as_table) else {
        return Vec::new();
    };
    let version = |v: &toml::Value| match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) => t.get("version")?.as_str().map(str::to_string),
        _ => None,
    };
    let mut out = Vec::new();
    for (tool, v) in tools {
        let reqs: Vec<String> = match v {
            toml::Value::Array(a) => a.iter().filter_map(version).collect(),
            other => version(other).into_iter().collect(),
        };
        out.extend(reqs.into_iter().map(|r| (tool.clone(), r)));
    }
    out
}

/// `tool` without mise's `core:` backend prefix.
fn short_tool(tool: &str) -> &str {
    tool.strip_prefix("core:").unwrap_or(tool)
}

/// Whether the request `req` selects `version`: equal, or a prefix ending at a `.`
/// (`20` → `20.11.0`, `3.12` → `3.12.15`, but `2` does not select `20.11.0`).
fn requests(req: &str, version: &str) -> bool {
    version == req
        || version
            .strip_prefix(req)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Findings of the installed mise versions (see the module docs). Nothing (and no
/// command run) when `mise` is `None`, when the index does not cover `home`, or when
/// `home/.local/share/mise` does not exist — so a scan of a temporary tree never reaches
/// the real mise — and nothing when `mise ls --json` fails. When
/// `--all-sources` fails, the versions keep their single source and no version file
/// counts as untracked.
pub fn find(
    index: &Index,
    home: &Path,
    mise: Option<&Path>,
    claimed: &mut HashSet<NodeId>,
) -> Vec<Finding> {
    let Some(mise) = mise else {
        return Vec::new();
    };
    if index.find(home).is_none() || !home.join(DATA_DIR).is_dir() {
        return Vec::new();
    }
    let Some(ls) = crate::tools::run_capture(mise, &["ls", "--json"], TIMEOUT) else {
        return Vec::new();
    };
    let Ok(versions) = parse_ls(&ls) else {
        return Vec::new();
    };
    let all = crate::tools::run_capture(mise, &["ls", "--all-sources", "--json"], TIMEOUT);
    let (versions, untracked) = match all.as_deref().map(|a| (a, parse_ls(a))) {
        Some((all, Ok(every))) => {
            // Tracked = every file mise reports, including requests of missing versions.
            let tracked: HashSet<PathBuf> = every
                .into_iter()
                .flat_map(|v| v.sources)
                .map(|s| s.path)
                .collect();
            (
                merge_sources(versions, all),
                untracked_version_files(index, home, &tracked),
            )
        }
        _ => (merge_sources(versions, ""), Vec::new()),
    };
    find_with(&versions, &untracked, index, home, claimed)
}

/// One finding per installed version in `versions`, with `untracked` version files
/// (from [`untracked_version_files`]) attached to the versions they request. Each
/// version's install dir is claimed; a version whose dir an earlier pass already claimed
/// is left out, and one whose dir is not in the index gets sizes 0.
pub fn find_with(
    versions: &[MiseVersion],
    untracked: &[(PathBuf, String, String)],
    index: &Index,
    home: &Path,
    claimed: &mut HashSet<NodeId>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for v in versions.iter().filter(|v| v.installed) {
        let node = index.find(&v.install_path);
        if node.is_some_and(|id| is_claimed(index, claimed, id)) {
            continue;
        }
        out.push(version_finding(v, untracked, index, node, home));
        if let Some(id) = node {
            claimed.insert(id);
        }
    }
    out
}

/// A `Project` component shown with the version, never acted on.
fn project(title: String, path: &Path, note: Option<&str>) -> Component {
    Component {
        kind: ComponentKind::Project,
        title,
        path: Some(path.to_path_buf()),
        allocated: 0,
        freed_if_deleted: 0,
        modified: None,
        default_on: false,
        removal: ComponentRemoval::None,
        note: note.map(str::to_string),
        covered_by_cask: false,
    }
}

/// `"1 project"`, `"2 projects"`.
fn count(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

fn version_finding(
    v: &MiseVersion,
    untracked: &[(PathBuf, String, String)],
    index: &Index,
    node: Option<NodeId>,
    home: &Path,
) -> Finding {
    let mut components: Vec<Component> = v
        .sources
        .iter()
        .map(|s| project(format!("requested by {}", s.kind), &s.path, None))
        .collect();
    let mut n_untracked = 0;
    for (path, tool, req) in untracked {
        let matches = short_tool(tool) == short_tool(&v.tool) && requests(req, &v.version);
        if matches && !components.iter().any(|c| c.path.as_deref() == Some(path)) {
            let title = format!("requested by {} · {NOT_TRACKED}", file_label(path));
            components.push(project(title, path, Some(NOT_TRACKED)));
            n_untracked += 1;
        }
    }

    let status = status_of(v, home);
    let mut subtitle = match status {
        VersionStatus::Global => "global".to_string(),
        VersionStatus::Pinned(n) => format!("pinned in {}", count(n, "project")),
        VersionStatus::Unreferenced => "not referenced".to_string(),
    };
    if n_untracked > 0 {
        subtitle.push_str(&format!(" · {}", count(n_untracked, "untracked file")));
    }
    let mut explain = match status {
        VersionStatus::Global => format!("{GLOBAL_EXPLAIN}."),
        VersionStatus::Pinned(n) => format!(
            "Installed by mise and requested by {}; they need `mise install` again after removal.",
            count(n, "project")
        ),
        VersionStatus::Unreferenced => {
            "Installed by mise; no config file mise has seen requests it.".to_string()
        }
    };
    if n_untracked > 0 && status != VersionStatus::Global {
        explain.push_str(" Version files mise has not seen also request it.");
    }
    let removal = match status {
        VersionStatus::Global => Removal::None,
        _ => Removal::MiseUninstall {
            tool: v.tool.clone(),
            version: v.version.clone(),
        },
    };

    let category = Category::LanguageVersions;
    let label = SafetyLabel::AppData;
    let mut f = match node {
        Some(id) => node_finding(index, id, v.install_path.clone(), category, label, RULE_ID),
        None => {
            explain.push(' ');
            explain.push_str(SIZE_UNKNOWN);
            Finding {
                id: FindingId(String::new()),
                category,
                title: String::new(),
                subtitle: None,
                path: Some(v.install_path.clone()),
                node: None,
                allocated: 0,
                logical: 0,
                freed_if_deleted: 0,
                modified: None,
                label,
                rule_id: RULE_ID.to_string(),
                explain: String::new(),
                removal: Removal::None,
                flags: Vec::new(),
                components: Vec::new(),
            }
        }
    };
    f.id = FindingId::new("mise", &format!("{}@{}", v.tool, v.version));
    f.title = format!("{} {}", v.tool, v.version);
    f.subtitle = Some(subtitle);
    f.explain = explain;
    f.removal = removal;
    f.components = components;
    f
}
