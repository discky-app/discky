//! Uninstall sequences: an app finding (by [`AppSource`]), a mise tool version, and any
//! finding whose [`Component`]s are planned one by one (leftover groups, orphan package
//! receipts).
//!
//! Each step lands in a [`Bucket`]; [`super::plan_items_with_tools`] concatenates the
//! buckets in order (quit → vendor/source commands → trash → `defaults delete` →
//! `pkgutil --forget`), so the per-app order of spec §7/§8 holds across findings.
//! Only official mechanisms are planned: `brew uninstall`, `launchctl bootout`,
//! `defaults delete`, `pkgutil --forget`, `mise uninstall`, the vendor's own script and
//! the Trash. Admin commands always use fixed system paths and never a working directory.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{
    ALREADY_GONE, Bucket, Fingerprint, Step, StepFlags, StepKind, already_gone, bundle_component,
    display, path_step, removal_step, step,
};
use crate::config::{Config, RemovalMode};
use crate::findings::apps::{FLAG_APP_RUNNING, FLAG_ZAP_SHARED, cask, leftovers, pkg};
use crate::findings::{AppSource, Component, ComponentKind, ComponentRemoval, Finding, Removal};
use crate::tools;

const PKGUTIL: &str = "/usr/sbin/pkgutil";
const LAUNCHCTL: &str = "/bin/launchctl";
const DEFAULTS: &str = "/usr/bin/defaults";
const OSASCRIPT: &str = "/usr/bin/osascript";
const SH: &str = "/bin/sh";
/// System settings live here; deleting their domain needs root.
const SYSTEM_PREFERENCES: &str = "/Library/Preferences";
/// Rule id of mise version findings; a `Removal::None` one is the global version.
const RULE_MISE_VERSION: &str = "mise-version";
/// Skip reason of a mise version that is set globally.
pub const GLOBAL_MISE_VERSION: &str =
    "Global version — change it in ~/.config/mise/config.toml first";
/// Environment of every `brew` step: no self-update and no analytics during an uninstall.
const BREW_ENV: [(&str, &str); 2] = [
    ("HOMEBREW_NO_AUTO_UPDATE", "1"),
    ("HOMEBREW_NO_ANALYTICS", "1"),
];
/// Receipt files under these are never trashed (listed as "left in place").
const PROTECTED: [&str; 4] = ["/usr", "/Library/Apple", "/System", "/private"];
/// At most this many "left in place" warnings per step; the rest are counted.
const MAX_LEFT_IN_PLACE: usize = 10;
/// Directory extensions that are one item (a bundle), trashed as a whole.
const PACKAGE_EXTS: [&str; 12] = [
    "app",
    "appex",
    "bundle",
    "component",
    "framework",
    "kext",
    "mdimporter",
    "plugin",
    "prefpane",
    "qlgenerator",
    "saver",
    "xpc",
];

/// `(label, system)` → whether launchd has the job loaded.
pub type LoadedProbe = Box<dyn Fn(&str, bool) -> bool>;
/// A key (cask token, package id) → what the system records for it.
pub type Lookup<T> = Box<dyn Fn(&str) -> Vec<T>>;

/// What planning may look up outside the finding. [`PlanTools::detect`] uses the real
/// system (read-only lookups); tests pass fakes, e.g.
/// `PlanTools { brew: Some("/fake/brew".into()), ..PlanTools::default() }`.
pub struct PlanTools {
    /// `brew`, run as the user (non-interactive); `None` → the step is `TOOL_MISSING`.
    pub brew: Option<PathBuf>,
    /// `mise`, run as the user; `None` → the step is `TOOL_MISSING`.
    pub mise: Option<PathBuf>,
    /// Whether launchd has `(label, system)` loaded (see [`leftovers::is_loaded`]).
    pub launchctl_probe: LoadedProbe,
    /// Bundle ids of running apps.
    pub running: HashSet<String>,
    /// A cask's `uninstall.quit` bundle ids, by short token.
    pub cask_quit: Lookup<String>,
    /// Absolute paths of the files package receipt `id` installed.
    pub pkg_files: Lookup<PathBuf>,
    /// The user's home: package files under it are trashed with the app.
    pub home: Option<PathBuf>,
}

impl Default for PlanTools {
    /// Nothing installed, nothing loaded, nothing running, no package files, no home.
    fn default() -> PlanTools {
        PlanTools {
            brew: None,
            mise: None,
            launchctl_probe: Box::new(|_, _| false),
            running: HashSet::new(),
            cask_quit: Box::new(|_| Vec::new()),
            pkg_files: Box::new(|_| Vec::new()),
            home: None,
        }
    }
}

impl PlanTools {
    /// Real lookups: `brew`/`mise` by [`tools::tool_path`], `launchctl print` for loaded
    /// jobs, the Caskroom on disk for `uninstall.quit`, `pkgutil --files` for package
    /// files, `$HOME`. The running set is read (once) only when `want_running`.
    pub fn detect(want_running: bool) -> PlanTools {
        PlanTools {
            brew: tools::tool_path("brew"),
            mise: tools::tool_path("mise"),
            launchctl_probe: Box::new(|label, system| {
                leftovers::is_loaded(label, system, Some(Path::new(LAUNCHCTL)))
            }),
            running: if want_running {
                tools::running_app_bundle_ids()
            } else {
                HashSet::new()
            },
            cask_quit: Box::new(cask::caskroom_quit_ids),
            pkg_files: Box::new(|id| pkg::receipt_files(Path::new(PKGUTIL), id)),
            home: crate::paths::home_dir(),
        }
    }
}

/// Whether `f` is planned here rather than by the generic single-step planner: apps, mise
/// versions (also the global one, to explain the skip), and every finding with components.
pub(super) fn handles(f: &Finding) -> bool {
    matches!(
        f.removal,
        Removal::App { .. } | Removal::MiseUninstall { .. }
    ) || is_global_mise(f)
        || !f.components.is_empty()
}

/// Whether planning `f` may quit apps other than its own (and so needs the running set).
pub(super) fn wants_running(f: &Finding) -> bool {
    has_flag(f, FLAG_APP_RUNNING)
        && matches!(
            f.removal,
            Removal::App {
                source: AppSource::Cask { .. },
                ..
            }
        )
}

fn is_global_mise(f: &Finding) -> bool {
    f.removal == Removal::None && f.rule_id == RULE_MISE_VERSION
}

fn has_flag(f: &Finding, flag: &str) -> bool {
    f.flags.iter().any(|x| x == flag)
}

/// The steps of `f` for the `selected` component indices, each with its bucket, or the
/// reason it is skipped.
pub(super) fn plan_finding(
    f: &Finding,
    selected: &[usize],
    cfg: &Config,
    tools: &PlanTools,
) -> Result<Vec<(Bucket, Step)>, String> {
    if is_global_mise(f) {
        return Err(GLOBAL_MISE_VERSION.to_string());
    }
    let mut out = Out::default();
    match &f.removal {
        Removal::App {
            source,
            bundle,
            bundle_id,
        } => {
            if already_gone(f) {
                return Err(ALREADY_GONE.to_string());
            }
            plan_app(
                f,
                source,
                bundle,
                bundle_id.as_deref(),
                selected,
                cfg,
                tools,
                &mut out,
            )?;
        }
        Removal::MiseUninstall { tool, version } => {
            if already_gone(f) {
                return Err(ALREADY_GONE.to_string());
            }
            out.push(Bucket::Vendor, mise_step(f, tool, version, tools));
        }
        // Leftover groups and orphan receipts: the selected components only, never the
        // top-level paths as well.
        Removal::Trash { .. } => {
            component_steps(f, selected, cfg, tools, |_| false, &mut out)?;
        }
        _ => {
            if let Some(s) = removal_step(f, cfg)? {
                out.push(Bucket::of(&s), s);
            }
            component_steps(f, selected, cfg, tools, |_| false, &mut out)?;
        }
    }
    if out.steps.is_empty() {
        return Err(if out.missing > 0 {
            ALREADY_GONE.to_string()
        } else {
            "Nothing selected".to_string()
        });
    }
    if !out.warnings.is_empty()
        && let Some((_, first)) = out
            .steps
            .iter_mut()
            .find(|(_, s)| !matches!(s.kind, StepKind::Quit { .. }))
    {
        first.warnings.extend(out.warnings);
    }
    Ok(out.steps)
}

/// Steps collected for one finding, plus finding-level warnings (attached to its first
/// non-quit step) and how many selected components were already missing.
#[derive(Default)]
struct Out {
    steps: Vec<(Bucket, Step)>,
    warnings: Vec<String>,
    missing: usize,
}

impl Out {
    fn push(&mut self, bucket: Bucket, s: Step) {
        self.steps.push((bucket, s));
    }
}

/// Quit, own uninstaller, the source step (brew / package files / bundle), then the
/// components. See the module docs for the buckets.
#[allow(clippy::too_many_arguments)]
fn plan_app(
    f: &Finding,
    source: &AppSource,
    bundle: &Path,
    bundle_id: Option<&str>,
    selected: &[usize],
    cfg: &Config,
    tools: &PlanTools,
    out: &mut Out,
) -> Result<(), String> {
    let bundle_i = bundle_component(f);
    let bundle_on = bundle_i.is_none_or(|i| selected.contains(&i));

    if has_flag(f, FLAG_APP_RUNNING) {
        if let Some(id) = bundle_id {
            out.push(
                Bucket::Quit,
                quit_step(f, format!("Quit {} ({id})", f.title), id),
            );
        }
        if let AppSource::Cask { token, .. } = source {
            for id in (tools.cask_quit)(token) {
                if Some(id.as_str()) != bundle_id && tools.running.contains(&id) {
                    out.push(Bucket::Quit, quit_step(f, format!("Quit {id}"), &id));
                }
            }
        }
    }

    for &i in selected {
        let c = &f.components[i];
        if c.kind == ComponentKind::OwnUninstaller
            && let Some(path) = &c.path
        {
            own_uninstaller(f, i, path, out);
        }
    }

    // `--zap` only when brew would remove nothing the user left out: no shared zap paths
    // and every covered leftover selected.
    let zap = matches!(source, AppSource::Cask { .. })
        && bundle_on
        && !has_flag(f, FLAG_ZAP_SHARED)
        && f.components
            .iter()
            .enumerate()
            .filter(|&(i, c)| c.covered_by_cask && Some(i) != bundle_i)
            .all(|(i, _)| selected.contains(&i));
    if bundle_on {
        let bundle_freed =
            bundle_i.map_or(f.freed_if_deleted, |i| f.components[i].freed_if_deleted);
        let (bucket, mut s) = match source {
            AppSource::Cask { full_token, .. } => (
                Bucket::Vendor,
                brew_step(f, full_token, zap, bundle, selected, tools),
            ),
            AppSource::Pkg { pkg_ids } => (Bucket::Trash, pkg_step(f, bundle, pkg_ids, cfg, tools)),
            AppSource::AppStore | AppSource::Dragged => {
                (Bucket::Trash, path_step(f, &[bundle.to_path_buf()], cfg))
            }
        };
        let zapped = match source {
            AppSource::Cask { .. } => s.freed.unwrap_or(0),
            _ => 0,
        };
        s.freed = Some(bundle_freed + zapped);
        s.component = bundle_i;
        out.push(bucket, s);
    }

    let skip = |i: usize| {
        Some(i) == bundle_i
            || f.components[i].kind == ComponentKind::OwnUninstaller
            || (zap && f.components[i].covered_by_cask)
    };
    component_steps(f, selected, cfg, tools, skip, out)
}

fn quit_step(f: &Finding, description: String, bundle_id: &str) -> Step {
    let mut q = step(
        f,
        description,
        StepKind::Quit {
            bundle_id: bundle_id.to_string(),
        },
    );
    q.freed = None;
    q.flags |= StepFlags::INTERACTIVE;
    q
}

/// A `Command` step with no working directory and no environment.
fn command(f: &Finding, description: String, argv: Vec<String>) -> Step {
    step(
        f,
        description,
        StepKind::Command {
            argv,
            cwd: None,
            env: Vec::new(),
        },
    )
}

/// `.scpt` → `osascript <path>`, `.sh` → `sh <path>`; anything else (an uninstaller app)
/// is the user's to run: a warning, no step.
fn own_uninstaller(f: &Finding, i: usize, path: &Path, out: &mut Out) {
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    let program = match ext.as_deref() {
        Some("scpt") => OSASCRIPT,
        Some("sh") => SH,
        _ => {
            out.warnings.push(format!(
                "Run {}'s own uninstaller first ({})",
                f.title,
                display(path)
            ));
            return;
        }
    };
    if !Fingerprint::take(path).exists {
        out.missing += 1;
        return;
    }
    let mut s = command(
        f,
        format!("Run {}'s own uninstaller", f.title),
        vec![program.to_string(), path.to_string_lossy().into_owned()],
    );
    s.freed = None;
    s.freed_note = Some("Optional vendor step".to_string());
    s.component = Some(i);
    out.push(Bucket::Vendor, s);
}

/// `brew uninstall --cask [--zap] <full_token>`, as the user. With `zap`, brew also
/// removes the covered leftovers: `freed` is their sum (the caller adds the bundle).
fn brew_step(
    f: &Finding,
    full_token: &str,
    zap: bool,
    bundle: &Path,
    selected: &[usize],
    tools: &PlanTools,
) -> Step {
    let program = tools
        .brew
        .as_deref()
        .map_or_else(|| "brew".to_string(), |p| p.to_string_lossy().into_owned());
    let mut argv = vec![program, "uninstall".to_string(), "--cask".to_string()];
    if zap {
        argv.push("--zap".to_string());
    }
    argv.push(full_token.to_string());
    let covered: Vec<&Component> = if zap {
        selected
            .iter()
            .map(|&i| &f.components[i])
            .filter(|c| c.covered_by_cask && c.kind != ComponentKind::AppBundle)
            .collect()
    } else {
        Vec::new()
    };
    let description = if zap {
        format!("Remove {} with Homebrew (zap)", f.title)
    } else {
        format!("Remove {} with Homebrew", f.title)
    };
    let mut s = step(
        f,
        description,
        StepKind::Command {
            argv,
            cwd: None,
            env: BREW_ENV
                .iter()
                .map(|&(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        },
    );
    // The covered leftovers only; the caller adds the bundle.
    s.freed = Some(covered.iter().map(|c| c.freed_if_deleted).sum::<u64>());
    // The bundle first: it is the measured target (see `execute::command_target`).
    s.fingerprints = std::iter::once(bundle)
        .chain(covered.iter().filter_map(|c| c.path.as_deref()))
        .map(Fingerprint::take)
        .collect();
    if tools.brew.is_none() {
        s.flags |= StepFlags::TOOL_MISSING;
        s.warnings.push("brew not found.".to_string());
    }
    s
}

/// One trash step for the bundle plus every file the packages installed under
/// `/Applications` or the home folder that still exists; files under system folders are
/// listed as left in place.
fn pkg_step(
    f: &Finding,
    bundle: &Path,
    pkg_ids: &[String],
    cfg: &Config,
    tools: &PlanTools,
) -> Step {
    let files: Vec<PathBuf> = pkg_ids
        .iter()
        .flat_map(|id| (tools.pkg_files)(id))
        .collect();
    let (extra, left) = pkg_paths(&files, bundle, tools.home.as_deref());
    let mut paths = vec![bundle.to_path_buf()];
    paths.extend(extra);
    let mut s = path_step(f, &paths, cfg);
    if paths.len() > 1 {
        let n = paths.len() - 1;
        let files = if n == 1 { "file" } else { "files" };
        s.description = match cfg.removal.mode {
            RemovalMode::Trash => {
                format!("Move {} and {n} installed {files} to the Trash", f.title)
            }
            RemovalMode::Permanent => {
                format!("Delete {} and {n} installed {files} permanently", f.title)
            }
        };
    }
    let shown = left.len().min(MAX_LEFT_IN_PLACE);
    s.warnings.extend(
        left[..shown]
            .iter()
            .map(|p| format!("left in place: {}", display(p))),
    );
    if left.len() > shown {
        s.warnings
            .push(format!("left in place: {} more files", left.len() - shown));
    }
    s
}

/// From a receipt's `files`: the existing paths to trash besides `bundle` (files,
/// symlinks and bundles under `/Applications/` or `home`, never plain directories, which
/// the receipt also lists when they existed before; never another app bundle; nothing
/// inside an already chosen path), and the protected paths left in place.
fn pkg_paths(
    files: &[PathBuf],
    bundle: &Path,
    home: Option<&Path>,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = home.filter(|h| h.is_absolute() && h.parent().is_some());
    let mut take = Vec::new();
    let mut left = Vec::new();
    for p in files {
        if p.starts_with(bundle) {
            continue;
        }
        let meta = std::fs::symlink_metadata(p);
        let is_dir = meta.as_ref().is_ok_and(|m| m.is_dir());
        if PROTECTED.iter().any(|root| p.starts_with(root)) {
            if !is_dir {
                left.push(p.clone());
            }
            continue;
        }
        let under_apps = p.starts_with("/Applications") && p != Path::new("/Applications");
        let under_home = home.is_some_and(|h| p.starts_with(h) && p != h);
        if !(under_apps || under_home) || meta.is_err() {
            continue;
        }
        let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase());
        let package = ext.as_deref().is_some_and(|e| PACKAGE_EXTS.contains(&e));
        if is_dir && !package {
            continue;
        }
        if ext.as_deref() == Some("app") {
            // Another app the same package installed stays.
            left.push(p.clone());
            continue;
        }
        take.push(p.clone());
    }
    take.sort();
    take.dedup();
    let mut kept: Vec<PathBuf> = Vec::new();
    for p in take {
        if !kept.iter().any(|k| p.starts_with(k)) {
            kept.push(p);
        }
    }
    left.retain(|p| !p.starts_with(bundle));
    (kept, left)
}

/// `mise uninstall <tool>@<version>`, as the user.
fn mise_step(f: &Finding, tool: &str, version: &str, tools: &PlanTools) -> Step {
    let spec = format!("{tool}@{version}");
    let program = tools
        .mise
        .as_deref()
        .map_or_else(|| "mise".to_string(), |p| p.to_string_lossy().into_owned());
    let mut s = command(
        f,
        format!("Uninstall {tool} {version} with mise"),
        vec![program, "uninstall".to_string(), spec],
    );
    if tools.mise.is_none() {
        s.flags |= StepFlags::TOOL_MISSING;
        s.warnings.push("mise not found.".to_string());
    }
    s.fingerprints = f.path.iter().map(|p| Fingerprint::take(p)).collect();
    s
}

/// One or two steps per selected component not `skip`ped: Trash → trash step;
/// Bootout → `launchctl bootout` (only when loaded) then the plist's trash step;
/// Defaults → `defaults delete`; PkgForget → `pkgutil --forget`; None → nothing.
/// Components whose path no longer exists are left out (and counted as missing).
fn component_steps(
    f: &Finding,
    selected: &[usize],
    cfg: &Config,
    tools: &PlanTools,
    skip: impl Fn(usize) -> bool,
    out: &mut Out,
) -> Result<(), String> {
    for &i in selected {
        if skip(i) {
            continue;
        }
        let c = &f.components[i];
        let exists = c.path.as_deref().map(|p| Fingerprint::take(p).exists);
        match &c.removal {
            ComponentRemoval::None => {}
            ComponentRemoval::Trash => {
                let Some(path) = &c.path else {
                    return Err(format!("Component {i} has no path"));
                };
                if exists == Some(true) {
                    out.push(Bucket::Trash, component_trash(f, i, c, path, cfg));
                } else {
                    out.missing += 1;
                }
            }
            ComponentRemoval::Bootout { label, system } => {
                if (tools.launchctl_probe)(label, *system) {
                    out.push(Bucket::Vendor, bootout_step(f, i, label, *system));
                }
                match (&c.path, exists) {
                    (Some(path), Some(true)) => {
                        out.push(Bucket::Trash, component_trash(f, i, c, path, cfg));
                    }
                    (Some(_), _) => out.missing += 1,
                    _ => {}
                }
            }
            ComponentRemoval::Defaults { domain } => {
                if exists == Some(false) {
                    out.missing += 1;
                    continue;
                }
                out.push(Bucket::Defaults, defaults_step(f, i, c, domain));
            }
            ComponentRemoval::PkgForget { pkg_id } => {
                if exists == Some(false) {
                    out.missing += 1;
                    continue;
                }
                let mut s = command(
                    f,
                    format!("Forget package receipt {pkg_id}"),
                    vec![PKGUTIL.to_string(), "--forget".to_string(), pkg_id.clone()],
                );
                s.flags |= StepFlags::INTERACTIVE;
                s.freed = Some(c.freed_if_deleted);
                s.component = Some(i);
                s.fingerprints = c.path.iter().map(|p| Fingerprint::take(p)).collect();
                out.push(Bucket::Forget, s);
            }
        }
    }
    Ok(())
}

/// The trash (or permanent delete) step of component `i`, described by its title.
fn component_trash(f: &Finding, i: usize, c: &Component, path: &Path, cfg: &Config) -> Step {
    let mut s = path_step(f, &[path.to_path_buf()], cfg);
    let title = c.title.strip_suffix(" · active").unwrap_or(&c.title);
    s.description = match cfg.removal.mode {
        RemovalMode::Trash => format!("Move {title} to the Trash"),
        RemovalMode::Permanent => format!("Delete {title} permanently"),
    };
    s.freed = Some(c.freed_if_deleted);
    s.component = Some(i);
    s
}

/// `launchctl bootout gui/<uid>/<label>` as the user, or `system/<label>` as root.
fn bootout_step(f: &Finding, i: usize, label: &str, system: bool) -> Step {
    let (target, what) = if system {
        (format!("system/{label}"), "daemon")
    } else {
        // SAFETY: `getuid` has no preconditions.
        let uid = unsafe { libc::getuid() };
        (format!("gui/{uid}/{label}"), "agent")
    };
    let mut s = command(
        f,
        format!("Unload launch {what} {label}"),
        vec![LAUNCHCTL.to_string(), "bootout".to_string(), target],
    );
    if system {
        s.flags |= StepFlags::INTERACTIVE;
    }
    // Credited by the plist's trash step.
    s.freed = None;
    s.component = Some(i);
    s
}

/// `defaults delete <domain>` as the user; a system domain (its plist under
/// `/Library/Preferences`) is addressed by path and deleted as root.
fn defaults_step(f: &Finding, i: usize, c: &Component, domain: &str) -> Step {
    let system = c
        .path
        .as_deref()
        .is_some_and(|p| p.starts_with(SYSTEM_PREFERENCES));
    let target = match (&c.path, system) {
        (Some(p), true) if !domain.starts_with('/') => {
            p.with_extension("").to_string_lossy().into_owned()
        }
        _ => domain.to_string(),
    };
    let mut s = command(
        f,
        format!("Delete settings domain {domain}"),
        vec![DEFAULTS.to_string(), "delete".to_string(), target],
    );
    if system {
        s.flags |= StepFlags::INTERACTIVE;
    }
    s.freed = Some(c.freed_if_deleted);
    s.component = Some(i);
    s.fingerprints = c.path.iter().map(|p| Fingerprint::take(p)).collect();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkg_paths_keep_files_and_bundles_and_skip_plain_dirs() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let fw = home.join("Library/X.framework");
        std::fs::create_dir_all(fw.join("Versions")).unwrap();
        std::fs::write(fw.join("Versions/x"), b"x").unwrap();
        let bundle = t.path().join("Y.app");
        let files = vec![
            home.clone(),
            home.join("Library"),
            fw.clone(),
            fw.join("Versions"),
            fw.join("Versions/x"),
            bundle.join("Contents"),
            PathBuf::from("/usr/local/bin/y"),
            PathBuf::from("/usr"),
            PathBuf::from("/opt/elsewhere"),
        ];
        let (take, left) = pkg_paths(&files, &bundle, Some(&home));
        assert_eq!(take, [fw]);
        assert_eq!(left, [PathBuf::from("/usr/local/bin/y")]);
        // Without a usable home nothing under it is taken.
        let (take, _) = pkg_paths(&files, &bundle, Some(Path::new("/")));
        assert!(take.is_empty());
    }
}
