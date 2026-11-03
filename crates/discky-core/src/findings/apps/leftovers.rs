//! What an app leaves behind outside its bundle: folders and files in the `~/Library` and
//! `/Library` locations of spec §8, matched to an app by bundle id, cask zap path, launchd
//! label or (in `Application Support` / `Logs` only) the exact app name.
//!
//! Everything is read from the [`Index`]; the only external command is
//! `launchctl print` ([`is_loaded`]) for the few launchd plists that match. Keychain items
//! are never looked at.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::findings::{Component, ComponentKind, ComponentRemoval};
use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::tools::run_capture;

/// Folders under `~/Library` searched for leftovers.
pub const USER_LOCATIONS: [(&str, ComponentKind); 12] = [
    ("Application Support", ComponentKind::ApplicationSupport),
    ("Caches", ComponentKind::Caches),
    ("Preferences", ComponentKind::Preferences),
    ("Containers", ComponentKind::Container),
    ("Group Containers", ComponentKind::GroupContainer),
    ("Saved Application State", ComponentKind::SavedState),
    ("HTTPStorages", ComponentKind::HttpStorage),
    ("WebKit", ComponentKind::WebKit),
    ("Cookies", ComponentKind::Cookies),
    ("Logs", ComponentKind::Logs),
    ("LaunchAgents", ComponentKind::LaunchAgent),
    ("Application Scripts", ComponentKind::ApplicationScript),
];

/// Folders under `/Library` searched for leftovers (removing anything here needs admin).
pub const SYSTEM_LOCATIONS: [(&str, ComponentKind); 5] = [
    ("LaunchAgents", ComponentKind::LaunchAgent),
    ("LaunchDaemons", ComponentKind::LaunchDaemon),
    ("Application Support", ComponentKind::ApplicationSupport),
    ("PrivilegedHelperTools", ComponentKind::PrivilegedHelper),
    ("Preferences", ComponentKind::Preferences),
];

/// The system library searched by [`leftovers_for`].
pub const SYSTEM_LIBRARY: &str = "/Library";
/// `launchctl`, asked by [`leftovers_for`] whether a matched job is loaded.
pub const LAUNCHCTL: &str = "/bin/launchctl";

pub const NOTE_ADMIN: &str = "needs administrator password";
pub const NOTE_DOCUMENTS: &str = "may hold documents";
/// A `Container` larger than this is left unselected ([`NOTE_DOCUMENTS`]).
const BIG_CONTAINER: u64 = 100 * 1024 * 1024;
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(2);
/// Suffixes dropped before a file name is read as a bundle id.
const ID_SUFFIXES: [&str; 3] = [".plist", ".savedState", ".binarycookies"];

/// Who is asking for leftovers.
pub struct LeftoverQuery<'a> {
    pub bundle_id: Option<&'a str>,
    /// The app's name as Finder shows it (`zoom.us`, `TeamViewer`).
    pub name: &'a str,
    /// Existing paths from the cask's `zap` stanza (already expanded).
    pub zap_paths: &'a [PathBuf],
    /// launchd labels from the cask's `uninstall` / `zap` stanzas.
    pub cask_launchctl: &'a [String],
}

/// The leftovers of one app in the user and system locations (see the module docs), as
/// components sorted by size, largest first. `installed_ids` are the bundle ids of the
/// other installed apps: a leftover one of them also matches is not removed with this
/// app (`removal: None`, "shared with …"). Asks `/bin/launchctl` about matched jobs.
pub fn leftovers_for(
    index: &Index,
    home: &Path,
    q: &LeftoverQuery,
    installed_ids: &HashSet<String>,
) -> Vec<Component> {
    let launchctl = Path::new(LAUNCHCTL);
    let cands = Candidates::gather(
        index,
        home,
        Path::new(SYSTEM_LIBRARY),
        launchctl.exists().then_some(launchctl),
    );
    let installed = Installed::from_ids(installed_ids.iter().map(|id| (id.clone(), humanise(id))));
    attach(index, &cands, q, &installed)
        .into_iter()
        .map(|l| l.component)
        .collect()
}

/// `Label` and `AssociatedBundleIdentifiers` of a launchd plist; `None` when the file is
/// not a plist dictionary with a string `Label`.
pub fn launchd_label(plist: &Path) -> Option<(String, Vec<String>)> {
    let job = read_launchd(plist)?;
    Some((job.label, job.associated))
}

/// Whether launchd has `label` loaded: `launchctl print gui/<uid>/<label>` (or
/// `system/<label>`) exits 0 within 2 s. `None` (no launchctl) → `false`.
pub fn is_loaded(label: &str, system: bool, launchctl: Option<&Path>) -> bool {
    let Some(launchctl) = launchctl else {
        return false;
    };
    let target = if system {
        format!("system/{label}")
    } else {
        // SAFETY: `getuid` has no preconditions.
        format!("gui/{}/{label}", unsafe { libc::getuid() })
    };
    run_capture(launchctl, &["print", &target], LAUNCHCTL_TIMEOUT).is_some()
}

/// The preference domains of `bundle_id`: `~/Library/Preferences/<id>*.plist` (the id
/// itself or a dotted extension of it, compared case-insensitively) as `(domain, path)`,
/// sorted. Read from the directory; never `defaults domains` (seconds slow).
pub fn preference_domains(home: &Path, bundle_id: &str) -> Vec<(String, PathBuf)> {
    let dir = home.join("Library/Preferences");
    let id = bundle_id.to_lowercase();
    let mut out: Vec<(String, PathBuf)> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let domain = name.strip_suffix(".plist")?;
            (has_id_prefix(&domain.to_lowercase(), &id) && e.path().is_file())
                .then(|| (domain.to_string(), e.path()))
        })
        .collect();
    out.sort();
    out
}

/// Bundle id → display name of every `.app` in `dirs` (each searched `depth` levels: 1 =
/// top level only, 2 = also one subfolder), read straight from `Contents/Info.plist`
/// (symlinked and sealed bundles included — this is about what is installed, not what can
/// be removed).
pub fn installed_bundle_ids(dirs: &[(&Path, usize)]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for &(dir, depth) in dirs {
        collect_bundle_ids(dir, depth, &mut out);
    }
    out
}

fn collect_bundle_ids(dir: &Path, depth: usize, out: &mut HashMap<String, String>) {
    if depth == 0 {
        return;
    }
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if let Some(stem) = name.strip_suffix(".app") {
            if let Ok(v) = plist::Value::from_file(path.join("Contents/Info.plist"))
                && let Some(id) = v
                    .as_dictionary()
                    .and_then(|d| d.get("CFBundleIdentifier"))
                    .and_then(|v| v.as_string())
            {
                out.entry(id.to_string())
                    .or_insert_with(|| stem.to_string());
            }
        } else if path.is_dir() {
            collect_bundle_ids(&path, depth - 1, out);
        }
    }
}

/// A parsed launchd job.
#[derive(Debug, Clone)]
pub(crate) struct LaunchdJob {
    pub label: String,
    pub associated: Vec<String>,
    /// `Program`, else `ProgramArguments[0]`.
    pub program: Option<PathBuf>,
}

fn read_launchd(plist: &Path) -> Option<LaunchdJob> {
    let v = plist::Value::from_file(plist).ok()?;
    let d = v.as_dictionary()?;
    let label = d.get("Label")?.as_string()?.to_string();
    let associated = match d.get("AssociatedBundleIdentifiers") {
        Some(plist::Value::String(s)) => vec![s.clone()],
        Some(plist::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_string().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let program = d
        .get("Program")
        .and_then(|v| v.as_string())
        .or_else(|| {
            d.get("ProgramArguments")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_string())
        })
        .map(PathBuf::from);
    Some(LaunchdJob {
        label,
        associated,
        program,
    })
}

/// One entry directly inside a leftover location.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub kind: ComponentKind,
    /// The location folder's name, e.g. `Application Support`.
    pub location: &'static str,
    /// Under the system library.
    pub system: bool,
    pub path: PathBuf,
    pub node: NodeId,
    pub name: String,
    /// The name with a leading `.`, a team prefix (`SY64MV22J9.`), `group.` and an
    /// [`ID_SUFFIXES`] suffix removed; original case.
    pub stem: String,
    /// `stem` lowercased.
    pub norm: String,
    pub launchd: Option<LaunchdJob>,
}

/// Every entry of the leftover locations, read once from the index and shared by all
/// apps (plus the launchctl path for [`is_loaded`]).
pub(crate) struct Candidates {
    pub items: Vec<Candidate>,
    pub launchctl: Option<PathBuf>,
}

impl Candidates {
    pub fn gather(
        index: &Index,
        home: &Path,
        system_library: &Path,
        launchctl: Option<&Path>,
    ) -> Candidates {
        let user = home.join("Library");
        let mut items = Vec::new();
        let places = USER_LOCATIONS
            .iter()
            .map(|(l, k)| (user.as_path(), *l, k, false))
            .chain(
                SYSTEM_LOCATIONS
                    .iter()
                    .map(|(l, k)| (system_library, *l, k, true)),
            );
        for (base, location, kind, system) in places {
            let dir = base.join(location);
            let Some(dir_id) = index.find(&dir) else {
                continue;
            };
            for id in index.children(dir_id) {
                let name = index.name(id).to_string_lossy().into_owned();
                if name == ".DS_Store" || name == ".localized" {
                    continue;
                }
                let path = dir.join(&name);
                let stem = id_stem(&name);
                let launchd = matches!(
                    kind,
                    ComponentKind::LaunchAgent | ComponentKind::LaunchDaemon
                )
                .then(|| read_launchd(&path))
                .flatten();
                items.push(Candidate {
                    kind: kind.clone(),
                    location,
                    system,
                    norm: stem.to_lowercase(),
                    stem,
                    path,
                    node: id,
                    name,
                    launchd,
                });
            }
        }
        Candidates {
            items,
            launchctl: launchctl.map(Path::to_path_buf),
        }
    }
}

/// Installed (or otherwise in-use) bundle ids, lowercased, with a display name.
#[derive(Debug, Default)]
pub(crate) struct Installed {
    by_id: HashMap<String, String>,
    /// Display names, lowercase without spaces.
    names: HashSet<String>,
}

impl Installed {
    pub fn from_ids(ids: impl IntoIterator<Item = (String, String)>) -> Installed {
        let mut out = Installed::default();
        for (id, name) in ids {
            out.insert(&id, &name);
        }
        out
    }

    pub fn insert(&mut self, id: &str, name: &str) {
        let key: String = name
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_lowercase();
        if key.len() >= 3 {
            self.names.insert(key);
        }
        self.by_id
            .entry(id.to_lowercase())
            .or_insert_with(|| name.to_string());
    }

    /// The longest installed id `norm` starts with (component-wise), with its name.
    fn owner(&self, norm: &str) -> Option<(&str, &str)> {
        self.by_id
            .iter()
            .filter(|(id, _)| has_id_prefix(norm, id))
            .max_by_key(|(id, _)| id.len())
            .map(|(id, n)| (id.as_str(), n.as_str()))
    }

    /// An installed app other than `own` that shares `norm`'s vendor: a bundle-id-like
    /// name with the same first two components (`com.google.Keystone` ↔
    /// `com.google.drivefs`), or a plain name equal to an id's vendor component (`Google`).
    fn vendor_sharer(&self, norm: &str, own: Option<&str>) -> Option<&str> {
        let mut hits: Vec<(&str, &str)> = self
            .by_id
            .iter()
            .filter(|(id, _)| Some(id.as_str()) != own)
            .filter(|(id, _)| match bundle_vendor(norm) {
                Some(v) => id_vendor(id) == v,
                None => id.split('.').nth(1) == Some(norm),
            })
            .map(|(id, n)| (id.as_str(), n.as_str()))
            .collect();
        hits.sort();
        hits.first().map(|(_, n)| *n)
    }

    /// Vendors (first two id components) of every id, plus [`SYSTEM_VENDORS`].
    pub fn vendors(&self) -> HashSet<String> {
        let mut v: HashSet<String> = self
            .by_id
            .keys()
            .map(|id| id_vendor(id).to_string())
            .collect();
        v.extend(SYSTEM_VENDORS.iter().map(|s| s.to_string()));
        v
    }

    /// Whether a component of `norm` is an installed app's name (lowercase, spaces
    /// removed): `org.amneziavpn.AmneziaVPN` while `AmneziaVPN.app` has another bundle id.
    pub fn names_app(&self, norm: &str) -> bool {
        norm.split('.').any(|part| self.names.contains(part))
    }
}

/// A component plus the logical size the finding's total needs.
#[derive(Debug, Clone)]
pub(crate) struct Leftover {
    pub component: Component,
    pub logical: u64,
}

/// [`leftovers_for`] over gathered candidates.
pub(crate) fn attach(
    index: &Index,
    cands: &Candidates,
    q: &LeftoverQuery,
    installed: &Installed,
) -> Vec<Leftover> {
    let bid = q.bundle_id.map(str::to_lowercase);
    let bid = bid.as_deref();
    let own = |norm: &str| bid.is_some_and(|b| has_id_prefix(norm, b));
    let mut picked: Vec<(&Candidate, bool /* own */)> = Vec::new();
    let mut labels: HashSet<String> = HashSet::new();
    let mut programs: HashSet<PathBuf> = HashSet::new();
    let mut seen: HashSet<&Path> = HashSet::new();
    // Launchd jobs and everything else first; helpers need the matched jobs.
    for c in cands
        .items
        .iter()
        .filter(|c| c.kind != ComponentKind::PrivilegedHelper)
    {
        let by_id = own(&c.norm);
        let by_zap = q.zap_paths.contains(&c.path);
        let by_name = matches!(c.location, "Application Support" | "Logs")
            && c.name.eq_ignore_ascii_case(q.name);
        let by_job = c.launchd.as_ref().is_some_and(|j| {
            bid.is_some_and(|b| {
                has_id_prefix(&j.label.to_lowercase(), b)
                    || j.associated.iter().any(|a| a.eq_ignore_ascii_case(b))
            }) || q
                .cask_launchctl
                .iter()
                .any(|l| l.eq_ignore_ascii_case(&j.label))
        });
        if !(by_id || by_zap || by_name || by_job) {
            continue;
        }
        if let Some(j) = &c.launchd {
            labels.insert(j.label.to_lowercase());
            programs.extend(j.program.clone());
        }
        picked.push((c, by_id || by_job));
        seen.insert(&c.path);
    }
    for c in cands
        .items
        .iter()
        .filter(|c| c.kind == ComponentKind::PrivilegedHelper)
    {
        let by_job = labels.contains(&c.norm) || programs.contains(&c.path);
        if own(&c.norm) || by_job || q.zap_paths.contains(&c.path) {
            picked.push((c, own(&c.norm) || by_job));
            seen.insert(&c.path);
        }
    }

    let mut out = Vec::new();
    for (c, owned) in picked {
        let shared = match sharing(&c.norm, owned, bid, installed) {
            Sharing::Other => continue,
            Sharing::With(name) => Some(name),
            Sharing::Mine => None,
        };
        let loaded = c.launchd.as_ref().is_some_and(|j| {
            is_loaded(
                &j.label,
                c.kind == ComponentKind::LaunchDaemon,
                cands.launchctl.as_deref(),
            )
        });
        out.push(leftover(index, c, shared, loaded));
    }
    // Zap paths outside the locations (e.g. `~/.config/raycast`).
    for p in q.zap_paths.iter().filter(|p| !seen.contains(p.as_path())) {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let norm = id_stem(&name).to_lowercase();
        let shared = match sharing(&norm, own(&norm), bid, installed) {
            Sharing::Other => continue,
            Sharing::With(n) => Some(n),
            Sharing::Mine => None,
        };
        out.push(other_leftover(index, p, shared));
    }
    drop_nested(&mut out);
    out.sort_by(|a, b| {
        b.component
            .allocated
            .cmp(&a.component.allocated)
            .then_with(|| a.component.path.cmp(&b.component.path))
    });
    out
}

enum Sharing {
    /// Removed with this app.
    Mine,
    /// Also used by the named app: listed, never removed.
    With(String),
    /// Belongs to another app (a longer bundle id matches): not listed.
    Other,
}

fn sharing(norm: &str, owned: bool, bid: Option<&str>, installed: &Installed) -> Sharing {
    let owner = installed.owner(norm).filter(|(id, _)| Some(*id) != bid);
    if owned {
        // `com.foo.app.helper` belongs to `com.foo.app.helper`, not `com.foo.app`.
        return match owner {
            Some((id, _)) if bid.is_some_and(|b| id.len() > b.len()) => Sharing::Other,
            _ => Sharing::Mine,
        };
    }
    if let Some((_, name)) = owner {
        return Sharing::With(name.to_string());
    }
    match installed.vendor_sharer(norm, bid) {
        Some(name) => Sharing::With(name.to_string()),
        None => Sharing::Mine,
    }
}

/// Sizes and dates of `id`: aggregates for a directory, its own for a file.
pub(crate) fn node_sizes(index: &Index, id: NodeId) -> (u64, u64, u64, i64) {
    let n = index.node(id);
    if n.kind == ObjKind::Dir {
        (n.agg_allocated, n.agg_logical, n.agg_private, n.max_mtime)
    } else {
        (n.allocated, n.logical, n.private, n.mtime)
    }
}

fn leftover(index: &Index, c: &Candidate, shared: Option<String>, loaded: bool) -> Leftover {
    let (allocated, logical, private, modified) = node_sizes(index, c.node);
    let mut title = match c.kind {
        ComponentKind::LaunchAgent => "LaunchAgent".to_string(),
        ComponentKind::LaunchDaemon => "LaunchDaemon".to_string(),
        ComponentKind::PrivilegedHelper => "Privileged helper".to_string(),
        _ => c.location.to_string(),
    };
    if loaded {
        title.push_str(" · active");
    }
    let removal = if shared.is_some() {
        ComponentRemoval::None
    } else {
        candidate_removal(c)
    };
    let big_container = c.kind == ComponentKind::Container && allocated > BIG_CONTAINER;
    let admin =
        c.system || c.kind == ComponentKind::LaunchDaemon || crate::plan::needs_admin(&c.path);
    let default_on = shared.is_none() && !big_container;
    let note = match shared {
        Some(name) => Some(format!("shared with {name}")),
        None if big_container => Some(NOTE_DOCUMENTS.to_string()),
        None if admin => Some(NOTE_ADMIN.to_string()),
        None => None,
    };
    Leftover {
        component: Component {
            kind: c.kind.clone(),
            title,
            path: Some(c.path.clone()),
            allocated,
            freed_if_deleted: private,
            modified: Some(modified),
            default_on,
            removal,
            note,
        },
        logical,
    }
}

/// How a candidate is removed: settings with `defaults delete`, launchd jobs booted out
/// (then trashed), everything else trashed.
pub(crate) fn candidate_removal(c: &Candidate) -> ComponentRemoval {
    match (&c.kind, &c.launchd) {
        (ComponentKind::Preferences, _) if c.name.ends_with(".plist") => {
            let domain = c.name.trim_end_matches(".plist");
            ComponentRemoval::Defaults {
                domain: if c.system {
                    // System settings are addressed by path: `defaults delete /Library/Preferences/x`.
                    c.path.with_file_name(domain).to_string_lossy().into_owned()
                } else {
                    domain.to_string()
                },
            }
        }
        (ComponentKind::LaunchAgent | ComponentKind::LaunchDaemon, Some(j)) => {
            ComponentRemoval::Bootout {
                label: j.label.clone(),
                system: c.kind == ComponentKind::LaunchDaemon,
            }
        }
        _ => ComponentRemoval::Trash,
    }
}

/// A zap path outside the searched locations.
fn other_leftover(index: &Index, path: &Path, shared: Option<String>) -> Leftover {
    let (allocated, logical, private, modified) = index
        .find(path)
        .map(|id| node_sizes(index, id))
        .map_or((0, 0, 0, None), |(a, l, p, m)| (a, l, p, Some(m)));
    let admin = shared.is_none() && crate::plan::needs_admin(path);
    Leftover {
        component: Component {
            kind: ComponentKind::Other,
            title: "Other files".to_string(),
            path: Some(path.to_path_buf()),
            allocated,
            freed_if_deleted: private,
            modified,
            default_on: shared.is_none(),
            removal: if shared.is_some() {
                ComponentRemoval::None
            } else {
                ComponentRemoval::Trash
            },
            note: match shared {
                Some(n) => Some(format!("shared with {n}")),
                None => admin.then(|| NOTE_ADMIN.to_string()),
            },
        },
        logical,
    }
}

/// Drop a leftover inside another selected one (it would be counted and trashed twice);
/// leftovers inside a shared (never removed) folder stay.
fn drop_nested(out: &mut Vec<Leftover>) {
    let owners: Vec<PathBuf> = out
        .iter()
        .filter(|l| l.component.removal != ComponentRemoval::None)
        .filter_map(|l| l.component.path.clone())
        .collect();
    out.retain(|l| {
        l.component
            .path
            .as_deref()
            .is_none_or(|p| !owners.iter().any(|o| o.as_path() != p && p.starts_with(o)))
    });
}

/// `name` without a leading `.`, a team prefix (`[A-Z0-9]{10}.`), `group.`/`groups.` and a
/// [`ID_SUFFIXES`] suffix.
pub(crate) fn id_stem(name: &str) -> String {
    let mut s = name.strip_prefix('.').unwrap_or(name);
    if let Some((team, rest)) = s.split_once('.')
        && team.len() == 10
        && team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        s = rest;
    }
    for group in ["group.", "groups."] {
        s = s.strip_prefix(group).unwrap_or(s);
    }
    for suffix in ID_SUFFIXES {
        s = s.strip_suffix(suffix).unwrap_or(s);
    }
    s.to_string()
}

/// `name` is `id` or a dotted extension of it (`com.x.app`, `com.x.app.helper`; not
/// `com.x.appx`). Both lowercase.
pub(crate) fn has_id_prefix(name: &str, id: &str) -> bool {
    !id.is_empty()
        && name
            .strip_prefix(id)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// Generic top-level domains seen in bundle ids (any two-letter one counts as well).
const GENERIC_TLDS: [&str; 22] = [
    "com", "org", "net", "edu", "gov", "info", "biz", "app", "dev", "xyz", "pro", "tech", "cloud",
    "design", "studio", "software", "systems", "tools", "page", "name", "team", "media",
];

/// Vendors whose files belong to macOS (Shortcuts is `is.workflow`, printing is CUPS),
/// developer toolchains, or frameworks and SDKs embedded in many apps (Sparkle, analytics):
/// never "leftovers of a removed app".
const SYSTEM_VENDORS: [&str; 16] = [
    "com.apple",
    "is.workflow",
    "org.cups",
    "org.swift",
    "org.python",
    "org.webkit",
    "org.chromium",
    "com.github.electron",
    "org.sparkle-project",
    "org.andymatuschak",
    "com.segment",
    "com.telemetrydeck",
    "io.branch",
    "io.sentry",
    "com.crashlytics",
    "com.mixpanel",
];

/// The vendor of a bundle-id-like lowercase name: its first two components
/// (`com.bitwarden` of `com.bitwarden.desktop`). `None` unless the name has at least
/// three components and starts with a two-letter or [`GENERIC_TLDS`] top-level domain
/// (so `copyq.log.1` or `notion.id.ShipIt` are not bundle ids).
pub(crate) fn bundle_vendor(norm: &str) -> Option<&str> {
    let mut parts = norm.split('.');
    let (tld, vendor, _) = (parts.next()?, parts.next()?, parts.next()?);
    let tld_ok = (tld.len() == 2 && tld.bytes().all(|b| b.is_ascii_lowercase()))
        || GENERIC_TLDS.contains(&tld);
    (tld_ok && !vendor.is_empty()).then(|| &norm[..tld.len() + 1 + vendor.len()])
}

/// First two components of an id (the whole id when it has fewer).
fn id_vendor(id: &str) -> &str {
    match id.match_indices('.').nth(1) {
        Some((i, _)) => &id[..i],
        None => id,
    }
}

/// Words that say nothing about which app a bundle id is.
const GENERIC: [&str; 12] = [
    "desktop", "macos", "mac", "osx", "app", "client", "helper", "agent", "shared", "group",
    "main", "plist",
];

/// A readable name from a bundle id: its last meaningful component, first letter upper
/// (`com.bitwarden.desktop` → "Bitwarden", `us.zoom` → "Zoom").
pub(crate) fn humanise(id: &str) -> String {
    let parts: Vec<&str> = id.split('.').filter(|p| !p.is_empty()).collect();
    let pick = parts
        .iter()
        .skip(1)
        .rev()
        .find(|p| {
            !GENERIC.contains(&p.to_lowercase().as_str()) && !p.bytes().all(|b| b.is_ascii_digit())
        })
        .or(parts.last())
        .copied()
        .unwrap_or(id);
    let mut chars = pick.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_stem_strips_team_group_and_suffixes() {
        assert_eq!(
            id_stem("SY64MV22J9.com.raycast.macos.shared"),
            "com.raycast.macos.shared"
        );
        assert_eq!(
            id_stem("group.net.whatsapp.WhatsApp.shared"),
            "net.whatsapp.WhatsApp.shared"
        );
        assert_eq!(
            id_stem(".com.raycast.macos.backups"),
            "com.raycast.macos.backups"
        );
        assert_eq!(id_stem("com.raycast.macos.plist"), "com.raycast.macos");
        assert_eq!(id_stem("us.zoom.xos.binarycookies"), "us.zoom.xos");
        assert_eq!(id_stem("com.apple.Preview.savedState"), "com.apple.Preview");
        assert_eq!(id_stem("LogiZoomBridge"), "LogiZoomBridge");
    }

    #[test]
    fn id_prefix_is_component_wise() {
        assert!(has_id_prefix("com.raycast.macos", "com.raycast.macos"));
        assert!(has_id_prefix(
            "com.raycast.macos.backups",
            "com.raycast.macos"
        ));
        assert!(!has_id_prefix("com.raycast.macosx", "com.raycast.macos"));
        assert!(!has_id_prefix("com.raycast", "com.raycast.macos"));
    }

    #[test]
    fn vendors_and_names() {
        assert_eq!(
            bundle_vendor("com.bitwarden.desktop"),
            Some("com.bitwarden")
        );
        assert_eq!(bundle_vendor("zoom.us"), None);
        assert_eq!(bundle_vendor("0dbc3339-0724"), None);
        assert_eq!(bundle_vendor("2bua8c4s2c.com.x"), None);
        assert_eq!(bundle_vendor("copyq.log.1"), None);
        assert_eq!(bundle_vendor("notion.id.shipit"), None);
        assert_eq!(bundle_vendor("pk.test.x"), Some("pk.test"));
        assert_eq!(
            id_stem("243LU875E5.groups.com.apple.podcasts"),
            "com.apple.podcasts"
        );
        assert_eq!(id_vendor("us.zoom.xos"), "us.zoom");
        assert_eq!(humanise("com.bitwarden.desktop"), "Bitwarden");
        assert_eq!(humanise("us.zoom"), "Zoom");
        assert_eq!(humanise("com.culturedcode.ThingsMac"), "ThingsMac");
    }
}
