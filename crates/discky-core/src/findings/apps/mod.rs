//! Installed applications: which bundles exist, how each got onto the Mac (Homebrew cask,
//! installer package, App Store, dragged in) and when it was last used.
//!
//! [`inventory`] is the entry point: it enumerates bundles from the [`Index`]
//! ([`inventory::app_bundles`]), asks `brew` ([`cask`]), `pkgutil` ([`pkg`]) and Spotlight
//! ([`last_used`]) at most once each, and [`assemble`]s one [`AppInfo`] per bundle. Every
//! external command is read-only and bounded (≤ 5 s); a missing tool just means less
//! information.
//!
//! [`find`] turns the inventory into findings (spec §6, §8): one per app with its bundle
//! and [`leftovers`] as components, one per group of leftovers whose app is gone, and one
//! for package receipts of removed apps. [`find_with`] is the same over inputs gathered
//! elsewhere (tests pass synthetic ones and never run a command).

pub mod cask;
pub mod inventory;
pub mod last_used;
pub mod leftovers;
pub mod pkg;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::findings::{
    AppSource, Component, ComponentKind, ComponentRemoval, Finding, FindingId, Removal, is_claimed,
    node_finding,
};
use crate::index::{Index, NodeId};
use crate::rules::{Category, SafetyLabel};
use crate::tools::tool_path;

use leftovers::{Candidates, Installed, LeftoverQuery, NOTE_ADMIN};

/// An app not opened for this many days counts as unused.
pub const UNUSED_DAYS: u32 = 180;
/// Flag of an app finding whose app is running (the planner quits it first).
pub const FLAG_APP_RUNNING: &str = "app-running";
/// Flag of a cask app finding whose `zap` stanza names a shared component: the planner
/// must run `brew uninstall --cask <token>` without `--zap` and trash the non-shared
/// covered components itself.
pub const FLAG_ZAP_SHARED: &str = "zap-shared";
/// `rule_id` of app findings.
pub const RULE_APP: &str = "apps";
/// `rule_id` of a leftover group of a removed app.
pub const RULE_LEFTOVERS: &str = "app-leftovers";
/// `rule_id` of the orphan package receipts finding.
pub const RULE_RECEIPTS: &str = "pkg-receipts";
/// A leftover group is shown when its components total at least this many bytes
/// allocated…
const GROUP_MIN_BYTES: u64 = 1024 * 1024;
/// …or when it has at least this many components.
const GROUP_MIN_ITEMS: usize = 3;
/// Apple's sealed apps (their bundle ids count as installed).
const SEALED_APPS: &str = "/System/Applications";

/// One installed application bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    /// Absolute path of the `.app` directory.
    pub bundle: PathBuf,
    /// The bundle's node in the index (sizes and dates come from there).
    pub node: NodeId,
    /// What Finder shows: the bundle's file name without `.app`.
    pub name: String,
    pub bundle_id: Option<String>,
    /// `CFBundleShortVersionString` of the bundle (brew's recorded version may lag behind
    /// an app that updates itself).
    pub version: Option<String>,
    pub source: AppSource,
    pub last_used: LastUsed,
    /// An uninstaller shipped with the app (see [`inventory::read_bundle`]).
    pub own_uninstaller: Option<PathBuf>,
    /// The bundle belongs to root: moving it to the Trash needs admin rights.
    pub root_owned: bool,
}

/// When an app was last used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LastUsed {
    /// Spotlight's `kMDItemLastUsedDate`, unix seconds.
    Spotlight(i64),
    /// No Spotlight date: the newest modification time among the app's leftovers.
    Estimated(i64),
    Unknown,
}

/// Absolute paths of the read-only tools the inventory asks; `None` = not available
/// (tests pass [`ToolPaths::default`], so nothing is run).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPaths {
    pub brew: Option<PathBuf>,
    pub pkgutil: Option<PathBuf>,
    pub mdfind: Option<PathBuf>,
    pub lsappinfo: Option<PathBuf>,
}

impl ToolPaths {
    /// Look each tool up with [`tool_path`], falling back to its standard macOS location
    /// (`/usr/sbin/pkgutil`, `/usr/bin/mdfind`, `/usr/bin/lsappinfo`): a GUI-launched
    /// process often has a bare `$PATH`.
    pub fn detect() -> ToolPaths {
        let find = |name: &str, fallback: &str| {
            tool_path(name).or_else(|| {
                let p = PathBuf::from(fallback);
                p.is_file().then_some(p)
            })
        };
        ToolPaths {
            brew: find("brew", "/opt/homebrew/bin/brew"),
            pkgutil: find("pkgutil", "/usr/sbin/pkgutil"),
            mdfind: find("mdfind", "/usr/bin/mdfind"),
            lsappinfo: find("lsappinfo", "/usr/bin/lsappinfo"),
        }
    }
}

/// Every installed app bundle under `/Applications` (and its direct subfolders) and
/// `~/Applications` that is in `index`, with its source and last-used date. Runs `brew`,
/// `pkgutil` and `mdfind` (each at most once, when its path is set); see the module docs.
pub fn inventory(index: &Index, home: &Path, tools: &ToolPaths) -> Vec<AppInfo> {
    gather(index, home, tools).apps
}

/// What [`gather`] collected: the apps, and the casks and receipts they came from (kept
/// for zap paths and orphan receipts, so brew and pkgutil run once).
#[derive(Debug, Clone, Default)]
pub struct Gathered {
    pub apps: Vec<AppInfo>,
    pub casks: Vec<cask::Cask>,
    pub receipts: Vec<pkg::PkgReceipt>,
}

/// [`inventory`] keeping the casks and receipts. No bundles → nothing is asked.
pub fn gather(index: &Index, home: &Path, tools: &ToolPaths) -> Gathered {
    let bundles = inventory::app_bundles(index, home);
    if bundles.is_empty() {
        return Gathered::default();
    }
    let casks = cask::installed_casks(tools.brew.as_deref());
    let receipts = pkg::receipts(tools.pkgutil.as_deref());
    let user_apps = home.join("Applications");
    let roots: Vec<&Path> = [Path::new(inventory::SYSTEM_APPS), user_apps.as_path()]
        .into_iter()
        .filter(|r| bundles.iter().any(|(_, b)| b.starts_with(r)))
        .collect();
    let spotlight = last_used::spotlight_last_used(tools.mdfind.as_deref(), &roots);
    let apps = assemble(&bundles, &casks, &receipts, &spotlight);
    Gathered {
        apps,
        casks,
        receipts,
    }
}

/// Whether the index covers `/Applications` or `<home>/Applications`. Without either
/// nothing is known about what is installed, so [`find`] (and the `running` lookup before
/// it) is skipped entirely.
pub fn applies(index: &Index, home: &Path) -> bool {
    index.find(Path::new(inventory::SYSTEM_APPS)).is_some()
        || index.find(&home.join("Applications")).is_some()
}

/// App findings for the categorizer (see the module docs); nothing when the index does
/// not cover `/Applications`. Runs the read-only inventory commands once, reads the
/// bundle ids of `/Applications`, `~/Applications` and `/System/Applications` and asks
/// `/bin/launchctl print` about matched launchd jobs. `running` are the bundle ids of
/// running apps. App findings claim nothing; leftover groups and receipts claim their
/// nodes.
pub fn find(
    index: &Index,
    home: &Path,
    claimed: &mut HashSet<NodeId>,
    running: &HashSet<String>,
) -> Vec<Finding> {
    if !applies(index, home) {
        return Vec::new();
    }
    let tools = ToolPaths::detect();
    let g = gather(index, home, &tools);
    let user_apps = home.join("Applications");
    let other_installed = leftovers::installed_bundle_ids(&[
        (Path::new(inventory::SYSTEM_APPS), 2),
        (user_apps.as_path(), 2),
        (Path::new(SEALED_APPS), 2),
    ]);
    let launchctl = Path::new(leftovers::LAUNCHCTL);
    find_with(
        index,
        home,
        claimed,
        &AppsInput {
            apps: &g.apps,
            casks: &g.casks,
            receipts: &g.receipts,
            running,
            other_installed: &other_installed,
            launchctl: launchctl.exists().then_some(launchctl),
            system_library: Path::new(leftovers::SYSTEM_LIBRARY),
            now: now_secs(),
        },
    )
}

/// Everything [`find_with`] needs besides the index.
pub struct AppsInput<'a> {
    pub apps: &'a [AppInfo],
    pub casks: &'a [cask::Cask],
    pub receipts: &'a [pkg::PkgReceipt],
    /// Bundle ids of running apps.
    pub running: &'a HashSet<String>,
    /// Bundle id → name of installed apps beyond `apps` (sealed, symlinked, nested ones);
    /// `apps` and `running` count as installed anyway.
    pub other_installed: &'a HashMap<String, String>,
    /// `launchctl` for [`leftovers::is_loaded`]; `None` = no job counts as loaded.
    pub launchctl: Option<&'a Path>,
    /// `/Library` (tests pass a temp dir).
    pub system_library: &'a Path,
    /// Unix seconds, for "last opened … ago".
    pub now: i64,
}

/// [`find`] over gathered inputs.
pub fn find_with(
    index: &Index,
    home: &Path,
    claimed: &mut HashSet<NodeId>,
    input: &AppsInput,
) -> Vec<Finding> {
    let mut installed = Installed::from_ids(
        input
            .other_installed
            .iter()
            .map(|(id, name)| (id.clone(), name.clone())),
    );
    for a in input.apps {
        if let Some(id) = &a.bundle_id {
            installed.insert(id, &a.name);
        }
    }
    for id in input.running {
        installed.insert_running(id, &leftovers::humanise(id));
    }
    let cands = Candidates::gather(index, home, input.system_library, input.launchctl);
    let mut out = Vec::new();
    let mut attached: HashSet<PathBuf> = HashSet::new();
    for app in input.apps {
        let f = app_finding(index, home, &cands, &installed, app, input);
        attached.extend(f.components.iter().filter_map(|c| c.path.clone()));
        out.push(f);
    }
    out.extend(leftover_groups(
        index, &cands, &installed, &attached, claimed,
    ));
    let bundles: HashSet<PathBuf> = input.apps.iter().map(|a| a.bundle.clone()).collect();
    out.extend(orphan_receipts_finding(input.receipts, &bundles));
    out
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The finding for one installed app: bundle, own uninstaller, leftovers (largest first),
/// pkg receipts, and the static Keychain line last.
fn app_finding(
    index: &Index,
    home: &Path,
    cands: &Candidates,
    installed: &Installed,
    app: &AppInfo,
    input: &AppsInput,
) -> Finding {
    let cask = match &app.source {
        AppSource::Cask { token, .. } => input.casks.iter().find(|c| &c.token == token),
        _ => None,
    };
    // `trash`/`delete` remove whatever is there; `rmdir` only an empty folder.
    let expand = |pick: fn(&cask::Directive) -> Vec<&String>| -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = cask
            .iter()
            .flat_map(|c| &c.zap)
            .flat_map(pick)
            .flat_map(|p| cask::expand_zap_path(p, home))
            .filter(|p| !p.starts_with(&app.bundle))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let zap_removed = expand(|d| d.trash.iter().chain(&d.delete).collect());
    let zap_rmdir = expand(|d| d.rmdir.iter().collect());
    let mut zap_paths: Vec<PathBuf> = zap_removed.iter().chain(&zap_rmdir).cloned().collect();
    zap_paths.sort();
    zap_paths.dedup();
    let cask_launchctl: Vec<String> = cask
        .map(|c| {
            c.uninstall
                .iter()
                .chain(&c.zap)
                .flat_map(|d| d.launchctl.iter().cloned())
                .collect()
        })
        .unwrap_or_default();
    let q = LeftoverQuery {
        bundle_id: app.bundle_id.as_deref(),
        name: &app.name,
        zap_paths: &zap_paths,
        cask_launchctl: &cask_launchctl,
    };
    let mut leftovers = leftovers::attach(index, cands, &q, installed);
    let mut zap_shared = false;
    for l in &mut leftovers {
        let zapped = l.component.path.as_deref().is_some_and(|p| {
            zap_removed.iter().any(|z| p.starts_with(z)) || zap_rmdir.iter().any(|z| z == p)
        });
        // A shared component is never removed by Discky, so it is never "covered": brew's
        // zap would delete it, which the flag tells the planner.
        if l.component.removal == ComponentRemoval::None {
            zap_shared |= zapped;
        } else {
            l.component.covered_by_cask = zapped;
        }
    }

    let running = app
        .bundle_id
        .as_deref()
        .is_some_and(|id| input.running.contains(id));
    let mut f = node_finding(
        index,
        app.node,
        app.bundle.clone(),
        Category::Apps,
        SafetyLabel::AppData,
        RULE_APP,
    );
    f.id = FindingId::new("app", &app.bundle.to_string_lossy());
    f.title = app.name.clone();

    let mut components = vec![Component {
        kind: ComponentKind::AppBundle,
        title: "Application".to_string(),
        path: Some(app.bundle.clone()),
        allocated: f.allocated,
        freed_if_deleted: f.freed_if_deleted,
        modified: f.modified,
        default_on: true,
        removal: ComponentRemoval::Trash,
        note: app.root_owned.then(|| NOTE_ADMIN.to_string()),
        covered_by_cask: matches!(app.source, AppSource::Cask { .. }),
    }];
    if let Some(u) = &app.own_uninstaller {
        components.push(Component {
            kind: ComponentKind::OwnUninstaller,
            title: "Own uninstaller".to_string(),
            path: Some(u.clone()),
            allocated: 0,
            freed_if_deleted: 0,
            modified: None,
            default_on: false,
            removal: ComponentRemoval::None,
            note: Some("run first to remove what the vendor installed".to_string()),
            covered_by_cask: false,
        });
    }
    let mut logical = f.logical;
    let mtimes: Vec<i64> = leftovers
        .iter()
        .filter_map(|l| l.component.modified)
        .collect();
    for l in leftovers {
        if l.component.default_on {
            logical += l.logical;
        }
        components.push(l.component);
    }
    if let AppSource::Pkg { pkg_ids } = &app.source {
        components.extend(pkg_ids.iter().map(|id| receipt_component(id, None)));
    }
    components.push(Component {
        kind: ComponentKind::Other,
        title: "Keychain items".to_string(),
        path: None,
        allocated: 0,
        freed_if_deleted: 0,
        modified: None,
        default_on: false,
        removal: ComponentRemoval::None,
        note: Some("never touched by Discky".to_string()),
        covered_by_cask: false,
    });

    let selected = || components.iter().filter(|c| c.default_on);
    f.allocated = selected().map(|c| c.allocated).sum();
    f.freed_if_deleted = selected().map(|c| c.freed_if_deleted).sum();
    f.logical = logical;
    let needs_password = app.root_owned
        || selected().any(|c| {
            c.kind == ComponentKind::LaunchDaemon || c.note.as_deref() == Some(NOTE_ADMIN)
        });
    f.label = if running {
        SafetyLabel::AppRunning
    } else if needs_password {
        SafetyLabel::NeedsPassword
    } else {
        SafetyLabel::AppData
    };
    if running {
        f.flags.push(FLAG_APP_RUNNING.to_string());
    }
    if zap_shared {
        f.flags.push(FLAG_ZAP_SHARED.to_string());
    }

    let last = match app.last_used {
        LastUsed::Unknown => last_used::estimate_from(&mtimes),
        known => known,
    };
    let (last_text, modified) = match last {
        LastUsed::Spotlight(t) => (format!("last opened {}", ago(t, input.now)), Some(t)),
        LastUsed::Estimated(t) => (format!("last opened {}*", ago(t, input.now)), Some(t)),
        LastUsed::Unknown => ("never opened*".to_string(), None),
    };
    f.subtitle = Some(format!("{} · {last_text}", source_text(&app.source)));
    f.modified = modified;
    f.explain = explain(&app.source);
    f.removal = Removal::App {
        source: app.source.clone(),
        bundle: app.bundle.clone(),
        bundle_id: app.bundle_id.clone(),
    };
    f.components = components;
    f
}

/// "cask · raycast", "pkg", "App Store", "drag & drop".
fn source_text(source: &AppSource) -> String {
    match source {
        AppSource::Cask { token, .. } => format!("cask · {token}"),
        AppSource::Pkg { .. } => "pkg".to_string(),
        AppSource::AppStore => "App Store".to_string(),
        AppSource::Dragged => "drag & drop".to_string(),
    }
}

/// How the app is removed, by source (spec §8).
fn explain(source: &AppSource) -> String {
    let how = match source {
        AppSource::Cask { full_token, .. } => format!(
            "Installed with Homebrew. Removed with `brew uninstall --zap {full_token}`, which \
             also deletes the leftovers the cask lists."
        ),
        AppSource::Pkg { pkg_ids } => format!(
            "Installed by an installer package ({}). Its files go to the Trash, then \
             `pkgutil --forget` drops the receipt.",
            pkg_ids.join(", ")
        ),
        AppSource::AppStore => {
            "From the App Store. The app goes to the Trash; it can be reinstalled from your \
             purchases."
                .to_string()
        }
        AppSource::Dragged => {
            "Copied into Applications by hand. The app goes to the Trash.".to_string()
        }
    };
    format!("{how} Settings are removed with `defaults delete`; Keychain items are never touched.")
}

/// "today", "yesterday", "N days ago", "N months ago" (up to two years), "N years ago".
fn ago(t: i64, now: i64) -> String {
    let days = (now - t).max(0) / 86_400;
    let plural = |n: i64, unit: &str| {
        if n == 1 {
            format!("1 {unit} ago")
        } else {
            format!("{n} {unit}s ago")
        }
    };
    match days {
        0 => "today".to_string(),
        1 => "yesterday".to_string(),
        2..=29 => plural(days, "day"),
        30..=729 => plural(days / 30, "month"),
        _ => plural(days / 365, "year"),
    }
}

/// A `pkgutil --forget` component for receipt `id`.
fn receipt_component(id: &str, installed: Option<i64>) -> Component {
    Component {
        kind: ComponentKind::Receipt,
        title: format!("Package receipt {id}"),
        path: Some(PathBuf::from(format!("/var/db/receipts/{id}.plist"))),
        allocated: 0,
        freed_if_deleted: 0,
        modified: installed,
        default_on: true,
        removal: ComponentRemoval::PkgForget {
            pkg_id: id.to_string(),
        },
        note: Some(NOTE_ADMIN.to_string()),
        covered_by_cask: false,
    }
}

/// One finding per vendor (first two bundle-id components) of unclaimed `~/Library`
/// entries that no installed app, running app or loaded launchd job uses (by vendor), that
/// do not name an installed app, and that are not macOS / toolchain / SDK files (see
/// [`leftovers::bundle_vendor`] and `SYSTEM_VENDORS`). Only groups of at least 1 MiB
/// allocated or 3 components are emitted; each emitted group claims its entries.
fn leftover_groups(
    index: &Index,
    cands: &Candidates,
    installed: &Installed,
    attached: &HashSet<PathBuf>,
    claimed: &mut HashSet<NodeId>,
) -> Vec<Finding> {
    let in_use = installed.vendors();
    let mut groups: BTreeMap<String, Vec<&leftovers::Candidate>> = BTreeMap::new();
    for c in cands.items.iter().filter(|c| !c.system) {
        let Some(vendor) = leftovers::bundle_vendor(&c.norm) else {
            continue;
        };
        if in_use.contains(vendor)
            || installed.names_app(&c.norm)
            || attached.contains(&c.path)
            || is_claimed(index, claimed, c.node)
        {
            continue;
        }
        groups.entry(vendor.to_string()).or_default().push(c);
    }
    let mut out = Vec::new();
    for (vendor, items) in groups {
        if vendor_job_loaded(cands, &vendor) {
            continue;
        }
        let f = group_finding(index, &vendor, &items);
        let total: u64 = f.components.iter().map(|c| c.allocated).sum();
        // Noise: one or two tiny files (a stray plist) are not worth a row; dropped groups
        // claim nothing.
        if total < GROUP_MIN_BYTES && f.components.len() < GROUP_MIN_ITEMS {
            continue;
        }
        out.push(f);
        claimed.extend(items.iter().map(|c| c.node));
    }
    out
}

/// Whether any launchd job (user or system) of `vendor` — by label or associated bundle id
/// — is loaded.
fn vendor_job_loaded(cands: &Candidates, vendor: &str) -> bool {
    cands.items.iter().any(|c| {
        c.launchd.as_ref().is_some_and(|j| {
            let ours = std::iter::once(&j.label)
                .chain(&j.associated)
                .any(|id| leftovers::bundle_vendor(&id.to_lowercase()) == Some(vendor));
            ours && leftovers::is_loaded(
                &j.label,
                c.kind == ComponentKind::LaunchDaemon,
                cands.launchctl.as_deref(),
            )
        })
    })
}

fn group_finding(index: &Index, vendor: &str, items: &[&leftovers::Candidate]) -> Finding {
    let mut components: Vec<(Component, u64)> = items
        .iter()
        .map(|c| {
            let (allocated, logical, private, modified) = leftovers::node_sizes(index, c.node);
            let removal = match leftovers::candidate_removal(c) {
                // Not loaded (checked above): the plist just goes to the Trash.
                ComponentRemoval::Bootout { .. } => ComponentRemoval::Trash,
                r => r,
            };
            let big = c.kind == ComponentKind::Container && allocated > 100 * 1024 * 1024;
            let component = Component {
                kind: c.kind.clone(),
                title: c.location.to_string(),
                path: Some(c.path.clone()),
                allocated,
                freed_if_deleted: private,
                modified: Some(modified),
                default_on: !big,
                removal,
                note: big.then(|| leftovers::NOTE_DOCUMENTS.to_string()),
                covered_by_cask: false,
            };
            (component, logical)
        })
        .collect();
    components.sort_by(|a, b| {
        b.0.allocated
            .cmp(&a.0.allocated)
            .then_with(|| a.0.path.cmp(&b.0.path))
    });
    let selected = || components.iter().filter(|(c, _)| c.default_on);
    let paths: Vec<PathBuf> = selected()
        .filter(|(c, _)| c.removal == ComponentRemoval::Trash)
        .filter_map(|(c, _)| c.path.clone())
        .collect();
    let mut ids: Vec<&str> = items.iter().map(|c| c.stem.as_str()).collect();
    ids.sort_by_key(|s| s.to_lowercase());
    ids.dedup_by_key(|s| app_id_of(s));
    let title = match ids.as_slice() {
        [one] => leftovers::humanise(&app_id_of(one)),
        _ => leftovers::humanise(vendor),
    };
    let n = components.len();
    Finding {
        id: FindingId::new("app-leftovers", vendor),
        category: Category::Apps,
        title,
        subtitle: Some(format!(
            "leftovers of a removed app · {n} {}",
            if n == 1 { "item" } else { "items" }
        )),
        path: None,
        node: None,
        allocated: selected().map(|(c, _)| c.allocated).sum(),
        logical: selected().map(|(_, l)| l).sum(),
        freed_if_deleted: selected().map(|(c, _)| c.freed_if_deleted).sum(),
        modified: components.iter().filter_map(|(c, _)| c.modified).max(),
        label: SafetyLabel::AppData,
        rule_id: RULE_LEFTOVERS.to_string(),
        explain: "No installed app found that uses these files.".to_string(),
        removal: Removal::Trash { paths },
        flags: Vec::new(),
        components: components.into_iter().map(|(c, _)| c).collect(),
    }
}

/// The first three components of a bundle-id-like stem (`com.bitwarden.desktop` of
/// `com.bitwarden.desktop.backups`), lowercased for comparison.
fn app_id_of(stem: &str) -> String {
    stem.split('.')
        .take(3)
        .collect::<Vec<_>>()
        .join(".")
        .to_lowercase()
}

/// "Package receipts of removed apps": one `pkgutil --forget` component per orphan.
fn orphan_receipts_finding(
    receipts: &[pkg::PkgReceipt],
    bundles: &HashSet<PathBuf>,
) -> Option<Finding> {
    let orphans = pkg::orphan_receipts(receipts, bundles);
    if orphans.is_empty() {
        return None;
    }
    let components: Vec<Component> = orphans
        .iter()
        .map(|r| receipt_component(&r.id, r.install_time))
        .collect();
    let n = components.len();
    Some(Finding {
        id: FindingId::new("pkg-receipts", "orphans"),
        category: Category::Apps,
        title: "Package receipts of removed apps".to_string(),
        subtitle: Some(format!(
            "{n} {}",
            if n == 1 { "receipt" } else { "receipts" }
        )),
        path: None,
        node: None,
        allocated: 0,
        logical: 0,
        freed_if_deleted: 0,
        modified: components.iter().filter_map(|c| c.modified).max(),
        label: SafetyLabel::NeedsPassword,
        rule_id: RULE_RECEIPTS.to_string(),
        explain: "Installer records of apps that are gone. `pkgutil --forget` drops the \
                  record only; no files are deleted."
            .to_string(),
        removal: Removal::Trash { paths: Vec::new() },
        flags: Vec::new(),
        components,
    })
}

/// Pure glue behind [`inventory`]: one [`AppInfo`] per bundle from already gathered
/// sources. Source priority: cask > pkg > App Store > dragged. `last_used` is the
/// Spotlight date or [`LastUsed::Unknown`] (leftover-based estimates come later).
pub fn assemble(
    bundles: &[(NodeId, PathBuf)],
    casks: &[cask::Cask],
    receipts: &[pkg::PkgReceipt],
    spotlight: &HashMap<PathBuf, i64>,
) -> Vec<AppInfo> {
    bundles
        .iter()
        .map(|(node, bundle)| {
            let meta = inventory::read_bundle(bundle);
            let pkgs = pkg::pkgs_for_bundle(receipts, bundle);
            let source = if let Some(c) = cask::cask_for_bundle(casks, bundle) {
                AppSource::Cask {
                    token: c.token.clone(),
                    full_token: c.full_token.clone(),
                }
            } else if !pkgs.is_empty() {
                AppSource::Pkg {
                    pkg_ids: pkgs.iter().map(|r| r.id.clone()).collect(),
                }
            } else if meta.mas_receipt {
                AppSource::AppStore
            } else {
                AppSource::Dragged
            };
            AppInfo {
                bundle: bundle.clone(),
                node: *node,
                name: bundle_display_name(bundle),
                bundle_id: meta.bundle_id,
                version: meta.version,
                source,
                last_used: last_used::resolve(spotlight.get(bundle).copied(), &[]),
                own_uninstaller: meta.own_uninstaller,
                root_owned: meta.root_owned,
            }
        })
        .collect()
}

/// `/Applications/zoom.us.app` ⇒ `zoom.us`.
fn bundle_display_name(bundle: &Path) -> String {
    let name = bundle
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.strip_suffix(".app") {
        Some(stem) => stem.to_string(),
        None => name,
    }
}
