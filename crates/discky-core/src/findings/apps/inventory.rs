//! Which `.app` bundles count as installed apps, and what their `Info.plist` says.

use std::os::macos::fs::MetadataExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};

/// The system-wide applications folder.
pub const SYSTEM_APPS: &str = "/Applications";
/// Apple's sealed apps; never inventoried even if a scan root reaches them.
const SEALED_APPS: &str = "/System/Applications";
/// `SF_RESTRICTED` in `st_flags` (`<sys/stat.h>`): protected by SIP.
const SF_RESTRICTED: u32 = 0x0008_0000;

/// What a bundle says about itself. Missing keys are `None` / `false`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleMeta {
    /// `CFBundleIdentifier`.
    pub bundle_id: Option<String>,
    /// `CFBundleName`.
    pub name: Option<String>,
    /// `CFBundleShortVersionString` (free-form, e.g. `6.6.10 (69071)`).
    pub version: Option<String>,
    /// `LSUIElement`: a menu-bar / agent app without a Dock icon.
    pub ui_element: bool,
    /// `Contents/_MASReceipt` exists: installed from the Mac App Store.
    pub mas_receipt: bool,
    /// The bundle directory is owned by root (uid 0).
    pub root_owned: bool,
    /// The app's own uninstaller, see [`read_bundle`].
    pub own_uninstaller: Option<PathBuf>,
}

/// `.app` directories directly under `/Applications`, under a direct subfolder of
/// `/Applications` (e.g. `/Applications/Adobe/X.app`), or directly under `~/Applications`
/// — as far as `index` covers them. Sorted by path. See [`app_bundles_in`] for the
/// exclusions.
pub fn app_bundles(index: &Index, home: &Path) -> Vec<(NodeId, PathBuf)> {
    app_bundles_in(index, Path::new(SYSTEM_APPS), &home.join("Applications"))
}

/// [`app_bundles`] with explicit folders: `system_apps` is searched one subfolder deep,
/// `user_apps` only at its top level. Never returned: symlinked bundles (Safari is a
/// restricted symlink into a Cryptex), bundles nested inside another bundle (only the
/// folders above are listed, and a `.app` is never treated as a subfolder), anything
/// under `/System/Applications`, and bundles with the `restricted` (SIP) flag. Only the
/// candidate bundles themselves are `lstat`-ed; enumeration uses the index.
pub fn app_bundles_in(
    index: &Index,
    system_apps: &Path,
    user_apps: &Path,
) -> Vec<(NodeId, PathBuf)> {
    let mut out = Vec::new();
    for (dir, with_subfolders) in [(system_apps, true), (user_apps, false)] {
        let Some(dir_id) = index.find(dir) else {
            continue;
        };
        if index.node(dir_id).kind != ObjKind::Dir {
            continue;
        }
        for child in index.children(dir_id) {
            if is_app_name(index, child) {
                out.push(child);
            } else if with_subfolders && index.node(child).kind == ObjKind::Dir {
                out.extend(index.children(child).filter(|&c| is_app_name(index, c)));
            }
        }
    }
    let mut bundles: Vec<(NodeId, PathBuf)> = out
        .into_iter()
        .filter(|&id| index.node(id).kind == ObjKind::Dir)
        .map(|id| (id, index.path(id)))
        .filter(|(_, p)| is_installable_bundle(p))
        .collect();
    bundles.sort_by(|a, b| a.1.cmp(&b.1));
    bundles.dedup_by(|a, b| a.1 == b.1);
    bundles
}

/// A visible entry named `*.app`.
fn is_app_name(index: &Index, id: NodeId) -> bool {
    let name = index.name(id).to_string_lossy();
    !name.starts_with('.') && name.to_ascii_lowercase().ends_with(".app")
}

/// The real-filesystem checks: not sealed, not a symlink, not `restricted`.
fn is_installable_bundle(path: &Path) -> bool {
    if path.starts_with(SEALED_APPS) {
        return false;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.is_dir() && m.st_flags() & SF_RESTRICTED == 0,
        Err(_) => false,
    }
}

/// Read the [`info_plist`] (tolerating a missing or malformed file), the App Store
/// receipt and ownership. `own_uninstaller` is the first that exists of: an
/// `Uninstall*.app|.scpt|.sh` in `Contents/Resources`, an executable (or `.app|.scpt|.sh`)
/// `Uninstall*` in `Contents/MacOS`, or a sibling `Uninstall <Name>.app` / `<Name> Uninstaller.app` next
/// to the bundle (names compared case-insensitively; `<Name>` is the bundle's file stem).
pub fn read_bundle(bundle: &Path) -> BundleMeta {
    let contents = bundle.join("Contents");
    let mut meta = BundleMeta::default();
    if let Some(info) = info_plist(bundle)
        && let Ok(v) = plist::Value::from_file(info)
        && let Some(d) = v.as_dictionary()
    {
        let s = |k: &str| d.get(k).and_then(|v| v.as_string()).map(str::to_string);
        meta.bundle_id = s("CFBundleIdentifier");
        meta.name = s("CFBundleName");
        meta.version = s("CFBundleShortVersionString");
        meta.ui_element = d.get("LSUIElement").is_some_and(truthy);
    }
    meta.mas_receipt = contents.join("_MASReceipt").is_dir();
    meta.root_owned = std::fs::symlink_metadata(bundle).is_ok_and(|m| m.uid() == 0);
    meta.own_uninstaller = own_uninstaller(bundle);
    meta
}

/// The bundle's `Info.plist`: `Contents/Info.plist`, or for an iOS/iPadOS app wrapped for
/// macOS (no `Contents/`) the inner bundle's — through the `WrappedBundle` symlink, else
/// the first `Wrapper/*.app/Info.plist`. `None` when there is none.
pub fn info_plist(bundle: &Path) -> Option<PathBuf> {
    let direct = bundle.join("Contents/Info.plist");
    if direct.is_file() {
        return Some(direct);
    }
    let wrapped = bundle.join("WrappedBundle/Info.plist");
    if wrapped.is_file() {
        return Some(wrapped);
    }
    sorted_entries(&bundle.join("Wrapper"))
        .into_iter()
        .filter(|p| lower_name(p).ends_with(".app"))
        .map(|p| p.join("Info.plist"))
        .find(|p| p.is_file())
}

/// `LSUIElement` appears as a boolean, an integer or a string (`"1"`, `"YES"`).
fn truthy(v: &plist::Value) -> bool {
    match v {
        plist::Value::Boolean(b) => *b,
        plist::Value::Integer(i) => i.as_signed().is_some_and(|i| i != 0),
        plist::Value::String(s) => matches!(s.to_ascii_lowercase().as_str(), "1" | "yes" | "true"),
        _ => false,
    }
}

fn own_uninstaller(bundle: &Path) -> Option<PathBuf> {
    let contents = bundle.join("Contents");
    let resources = sorted_entries(&contents.join("Resources"))
        .into_iter()
        .find(|p| {
            let n = lower_name(p);
            n.starts_with("uninstall") && is_script_or_app(&n)
        });
    if resources.is_some() {
        return resources;
    }
    let macos = sorted_entries(&contents.join("MacOS"))
        .into_iter()
        .find(|p| {
            let n = lower_name(p);
            n.starts_with("uninstall") && (is_script_or_app(&n) || is_executable_file(p))
        });
    if macos.is_some() {
        return macos;
    }
    let stem = bundle.file_stem()?.to_string_lossy().to_lowercase();
    let wanted = [
        format!("uninstall {stem}.app"),
        format!("{stem} uninstaller.app"),
    ];
    sorted_entries(bundle.parent()?)
        .into_iter()
        .find(|p| wanted.contains(&lower_name(p)))
}

fn is_script_or_app(lower_name: &str) -> bool {
    [".app", ".scpt", ".sh"]
        .iter()
        .any(|ext| lower_name.ends_with(ext))
}

/// A regular file with an execute bit (not e.g. `uninstall_conclusion.html`).
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn lower_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Entries of `dir`, sorted; empty when it cannot be read.
fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}
