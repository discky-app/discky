//! Installer-package receipts (`pkgutil`): which third-party packages are recorded and
//! which files they installed. Read-only: nothing here ever runs `pkgutil --forget`.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::tools::run_capture;

/// Budget for all `pkgutil` calls of one [`receipts`] run.
const PKGUTIL_BUDGET: Duration = Duration::from_secs(5);
const APPLICATIONS: &str = "/Applications";

/// One installed package receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgReceipt {
    pub id: String,
    pub version: String,
    pub volume: PathBuf,
    /// Relative to `volume`; may be empty, `Applications` or even `Applications/X.app`.
    pub location: PathBuf,
    pub install_time: Option<i64>,
    /// Absolute: `volume / location / <path from --files>`.
    pub files: Vec<PathBuf>,
}

/// Parse `pkgutil --pkg-info <id>` text into `(id, version, volume, location,
/// install_time)`. `None` without a `package-id` line.
pub fn parse_pkg_info(text: &str) -> Option<(String, String, PathBuf, PathBuf, Option<i64>)> {
    let mut id = None;
    let mut version = String::new();
    let mut volume = PathBuf::from("/");
    let mut location = PathBuf::new();
    let mut time = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "package-id" if !value.is_empty() => id = Some(value.to_string()),
            "version" => version = value.to_string(),
            "volume" if !value.is_empty() => volume = PathBuf::from(value),
            "location" => location = PathBuf::from(value),
            "install-time" => time = value.parse().ok(),
            _ => {}
        }
    }
    Some((id?, version, volume, location, time))
}

/// Third-party receipts (every id not starting with `com.apple.`): `pkgutil --pkgs`, then
/// `--pkg-info` and `--files` per id, all within one 5 s budget — when it runs out the
/// receipts read so far are returned. `None` (no pkgutil) → empty.
pub fn receipts(pkgutil: Option<&Path>) -> Vec<PkgReceipt> {
    let Some(pkgutil) = pkgutil else {
        return Vec::new();
    };
    let deadline = Instant::now() + PKGUTIL_BUDGET;
    let run = |args: &[&str]| {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        run_capture(pkgutil, args, left)
    };
    let Some(ids) = run(&["--pkgs"]) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for id in ids.lines().map(str::trim) {
        if id.is_empty() || id.starts_with("com.apple.") {
            continue;
        }
        if Instant::now() >= deadline {
            break;
        }
        let Some(info) = run(&["--pkg-info", id]).as_deref().and_then(parse_pkg_info) else {
            continue;
        };
        let Some(files) = run(&["--files", id]) else {
            continue;
        };
        let (id, version, volume, location, install_time) = info;
        let base = volume.join(&location);
        let files = files
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| base.join(l))
            .collect();
        out.push(PkgReceipt {
            id,
            version,
            volume,
            location,
            install_time,
            files,
        });
    }
    out
}

/// Absolute paths of the files package `id` installed: `pkgutil --pkg-info` (for its
/// volume and location) and `--files`, within one 5 s budget. Empty on any failure.
/// Read-only.
pub fn receipt_files(pkgutil: &Path, id: &str) -> Vec<PathBuf> {
    let deadline = Instant::now() + PKGUTIL_BUDGET;
    let run = |args: &[&str]| {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        run_capture(pkgutil, args, left)
    };
    let Some((_, _, volume, location, _)) =
        run(&["--pkg-info", id]).as_deref().and_then(parse_pkg_info)
    else {
        return Vec::new();
    };
    let Some(files) = run(&["--files", id]) else {
        return Vec::new();
    };
    let base = volume.join(location);
    files
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| base.join(l))
        .collect()
}

/// Receipts that installed `bundle` or anything inside it.
pub fn pkgs_for_bundle<'a>(receipts: &'a [PkgReceipt], bundle: &Path) -> Vec<&'a PkgReceipt> {
    receipts
        .iter()
        .filter(|r| r.files.iter().any(|f| f.starts_with(bundle)))
        .collect()
}

/// Receipts whose apps are all gone: they installed at least one bundle under
/// `/Applications` (directly or one subfolder deep), and none of those bundles is in
/// `installed` or still exists on disk. Receipts without files under `/Applications`
/// (drivers, helpers) are never orphans — there is nothing to compare against.
pub fn orphan_receipts<'a>(
    receipts: &'a [PkgReceipt],
    installed: &HashSet<PathBuf>,
) -> Vec<&'a PkgReceipt> {
    receipts
        .iter()
        .filter(|r| {
            let bundles: HashSet<PathBuf> =
                r.files.iter().filter_map(|f| app_bundle_of(f)).collect();
            !bundles.is_empty()
                && bundles
                    .iter()
                    .all(|b| !installed.contains(b) && std::fs::symlink_metadata(b).is_err())
        })
        .collect()
}

/// `/Applications/X.app/…` or `/Applications/<dir>/X.app/…` ⇒ that `.app`.
fn app_bundle_of(file: &Path) -> Option<PathBuf> {
    let rest = file.strip_prefix(APPLICATIONS).ok()?;
    let mut bundle = PathBuf::from(APPLICATIONS);
    for c in rest.components().take(2) {
        let Component::Normal(name) = c else {
            return None;
        };
        bundle.push(name);
        if name
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".app")
        {
            return Some(bundle);
        }
    }
    None
}
