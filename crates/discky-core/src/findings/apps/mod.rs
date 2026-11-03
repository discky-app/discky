//! Installed applications: which bundles exist, how each got onto the Mac (Homebrew cask,
//! installer package, App Store, dragged in) and when it was last used.
//!
//! [`inventory`] is the entry point: it enumerates bundles from the [`Index`]
//! ([`inventory::app_bundles`]), asks `brew` ([`cask`]), `pkgutil` ([`pkg`]) and Spotlight
//! ([`last_used`]) at most once each, and [`assemble`]s one [`AppInfo`] per bundle. Every
//! external command is read-only and bounded (≤ 5 s); a missing tool just means less
//! information. Turning apps into findings (and attaching leftovers) happens elsewhere.

pub mod cask;
pub mod inventory;
pub mod last_used;
// pub mod leftovers; — per-app leftovers (Task 3).
pub mod pkg;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::findings::AppSource;
use crate::index::{Index, NodeId};
use crate::tools::tool_path;

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
    let bundles = inventory::app_bundles(index, home);
    if bundles.is_empty() {
        return Vec::new();
    }
    let casks = cask::installed_casks(tools.brew.as_deref());
    let receipts = pkg::receipts(tools.pkgutil.as_deref());
    let user_apps = home.join("Applications");
    let roots: Vec<&Path> = [Path::new(inventory::SYSTEM_APPS), user_apps.as_path()]
        .into_iter()
        .filter(|r| bundles.iter().any(|(_, b)| b.starts_with(r)))
        .collect();
    let spotlight = last_used::spotlight_last_used(tools.mdfind.as_deref(), &roots);
    assemble(&bundles, &casks, &receipts, &spotlight)
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
