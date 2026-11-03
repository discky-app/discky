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
const RULE_MISE_VERSION: &str = crate::findings::mise::RULE_ID;
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

/// A cask's `zap` stanza as planning sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZapInfo {
    /// The existing paths its `trash` and `delete` directives expand to.
    pub paths: Vec<PathBuf>,
    /// Whether it also has directives that are not paths (`pkgutil`, `launchctl`,
    /// `script`, `early_script`, `signal`, `login_item`).
    pub non_path_directives: bool,
}

/// What `brew uninstall --cask` does besides removing the bundle, as planning sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaskInfo {
    pub zap: ZapInfo,
    /// The `uninstall` stanza as one-liners: "quit com.x", "launchctl com.x.agent",
    /// "pkgutil com.x.pkg", "delete /Library/…", "script /usr/bin/pkill …",
    /// "signal KILL com.x".
    pub uninstall_directives: Vec<String>,
    /// Existing app bundles the cask installed (the planner leaves out the finding's own).
    pub other_app_targets: Vec<PathBuf>,
    /// Existing binaries the cask linked.
    pub binaries: Vec<PathBuf>,
    /// The uninstall stanza needs an administrator: `pkgutil`, a system `launchctl` job,
    /// a root-owned `delete`/`trash` path, a `sudo` script.
    pub needs_admin: bool,
}

/// A cask's full token → what its uninstall does; `None` when it cannot be read.
pub type CaskLookup = Box<dyn Fn(&str) -> Option<CaskInfo>>;

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
    /// What a cask's uninstall does, by full token. `--zap` is used only when its zap
    /// stanza is known and removes nothing beyond the selected covered components; the
    /// rest becomes warnings on the brew step.
    pub cask_info: CaskLookup,
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
            cask_info: Box::new(|_| None),
            pkg_files: Box::new(|_| Vec::new()),
            home: None,
        }
    }
}

impl PlanTools {
    /// Real lookups: `brew`/`mise` by [`tools::tool_path`], `launchctl print` for loaded
    /// jobs, the Caskroom on disk for `uninstall.quit` and the cask's stanzas and artifacts,
    /// `pkgutil --files` for package
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
            cask_info: {
                let home = crate::paths::home_dir();
                Box::new(move |full_token| caskroom_info(full_token, home.as_deref()?))
            },
            pkg_files: Box::new(|id| pkg::receipt_files(Path::new(PKGUTIL), id)),
            home: crate::paths::home_dir(),
        }
    }
}

/// What brew's uninstall of `full_token` does, from the first default Caskroom (offline;
/// no `brew` run), `None` unless it was read from what brew will load (see
/// [`cask::installed_cask`]). Binaries named without a path live in `<prefix>/bin`, the
/// prefix being the Caskroom's parent.
fn caskroom_info(full_token: &str, home: &Path) -> Option<CaskInfo> {
    let token = full_token.rsplit('/').next()?;
    let room = cask::DEFAULT_CASKROOMS
        .iter()
        .map(Path::new)
        .find(|p| p.is_dir())?;
    let c = cask::installed_cask(room, token)?;
    let exists = |p: &PathBuf| std::fs::symlink_metadata(p).is_ok();
    let bin_dir = room.parent()?.join("bin");
    let binaries = c
        .binaries
        .iter()
        .map(|b| {
            let p = Path::new(b);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                bin_dir.join(p)
            }
        })
        .filter(exists)
        .collect();
    let (uninstall_directives, needs_admin) =
        uninstall_summary(&c.uninstall, home, Path::new(leftovers::SYSTEM_LIBRARY));
    Some(CaskInfo {
        zap: zap_info(&c.zap, home),
        uninstall_directives,
        other_app_targets: c.app_targets.into_iter().filter(exists).collect(),
        binaries,
        needs_admin,
    })
}

/// The `uninstall` stanza as one-liners, and whether it needs an administrator (see
/// [`CaskInfo`]); a `launchctl` job is a system one when its plist is in
/// `<system_library>/LaunchDaemons` or `LaunchAgents`.
fn uninstall_summary(
    directives: &[cask::Directive],
    home: &Path,
    system_library: &Path,
) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut admin = false;
    let script_line = |kind: &str, s: &cask::Script| {
        std::iter::once(kind.to_string())
            .chain(std::iter::once(s.executable.clone()))
            .chain(s.args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    };
    for d in directives {
        if let Some(s) = &d.early_script {
            lines.push(script_line("early_script", s));
            admin |= s.sudo;
        }
        lines.extend(d.quit.iter().map(|id| format!("quit {id}")));
        lines.extend(
            d.signal
                .iter()
                .map(|(sig, id)| format!("signal {sig} {id}")),
        );
        lines.extend(d.login_item.iter().map(|n| format!("login_item {n}")));
        for label in &d.launchctl {
            lines.push(format!("launchctl {label}"));
            admin |= ["LaunchDaemons", "LaunchAgents"].iter().any(|dir| {
                system_library
                    .join(dir)
                    .join(format!("{label}.plist"))
                    .exists()
            });
        }
        for id in &d.pkgutil {
            lines.push(format!("pkgutil {id}"));
            admin = true;
        }
        if let Some(s) = &d.script {
            lines.push(script_line("script", s));
            admin |= s.sudo;
        }
        for (kind, paths) in [
            ("delete", &d.delete),
            ("trash", &d.trash),
            ("rmdir", &d.rmdir),
        ] {
            for p in paths {
                lines.push(format!("{kind} {p}"));
                admin |= cask::expand_zap_path(p, home)
                    .iter()
                    .any(|x| super::needs_admin(x));
            }
        }
    }
    (lines, admin)
}

/// A zap stanza as planning sees it. `rmdir` directives are left out: they remove empty
/// folders only.
fn zap_info(zap: &[cask::Directive], home: &Path) -> ZapInfo {
    let mut paths: Vec<PathBuf> = zap
        .iter()
        .flat_map(|d| d.trash.iter().chain(&d.delete))
        .flat_map(|p| cask::expand_zap_path(p, home))
        .collect();
    paths.sort();
    paths.dedup();
    let non_path_directives = zap.iter().any(|d| {
        !d.pkgutil.is_empty()
            || !d.launchctl.is_empty()
            || d.script.is_some()
            || d.early_script.is_some()
            || !d.signal.is_empty()
            || !d.login_item.is_empty()
    });
    ZapInfo {
        paths,
        non_path_directives,
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
            bootout_steps(f, selected, tools, &mut out);
            component_steps(f, selected, cfg, |_| false, &mut out)?;
        }
        _ => {
            if let Some(s) = removal_step(f, cfg)? {
                out.push(Bucket::of(&s), s);
            }
            bootout_steps(f, selected, tools, &mut out);
            component_steps(f, selected, cfg, |_| false, &mut out)?;
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

    // Loaded jobs first, covered ones too: brew's own `launchctl` stanza tolerates a job
    // that is already gone, `launchctl bootout` does not.
    bootout_steps(f, selected, tools, out);

    for &i in selected {
        let c = &f.components[i];
        if c.removal == ComponentRemoval::RunScript {
            let Some(path) = &c.path else {
                return Err(format!("Component {i} has no path"));
            };
            own_uninstaller(f, i, path, out)?;
        }
    }

    // Package receipts that also installed another app that still exists are kept, with
    // their files.
    let mut pkg_files: Vec<PathBuf> = Vec::new();
    let mut shared_pkgs: HashSet<&str> = HashSet::new();
    if let AppSource::Pkg { pkg_ids } = source {
        for id in pkg_ids {
            let files = (tools.pkg_files)(id);
            let others = other_apps(&files, bundle);
            if others.is_empty() {
                pkg_files.extend(files);
            } else {
                shared_pkgs.insert(id);
                out.warnings.push(format!(
                    "Package {id} also installed {}; receipt kept",
                    others.join(", ")
                ));
            }
        }
    }

    let info = match source {
        AppSource::Cask { full_token, .. } if bundle_on => (tools.cask_info)(full_token),
        _ => None,
    };
    let (zap, zap_warning) = match source {
        AppSource::Cask { .. } if bundle_on => zap_decision(f, info.as_ref(), selected),
        _ => (false, None),
    };
    if bundle_on {
        let bundle_freed =
            bundle_i.map_or(f.freed_if_deleted, |i| f.components[i].freed_if_deleted);
        let (bucket, mut s) = match source {
            AppSource::Cask { full_token, .. } => (
                Bucket::Vendor,
                brew_step(f, full_token, zap, bundle, selected, info.as_ref(), tools),
            ),
            AppSource::Pkg { .. } => (Bucket::Trash, pkg_step(f, bundle, &pkg_files, cfg, tools)),
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
        s.warnings.extend(zap_warning);
        // An uninstaller app (or bare executable) is shown only: the user runs it.
        s.warnings.extend(
            f.components
                .iter()
                .filter(|c| c.kind == ComponentKind::OwnUninstaller)
                .filter(|c| c.removal == ComponentRemoval::None)
                .filter_map(|c| c.path.as_deref())
                .map(|p| format!("Run {}'s own uninstaller first ({})", f.title, display(p))),
        );
        out.push(bucket, s);
    }

    let skip = |i: usize| {
        let c = &f.components[i];
        Some(i) == bundle_i
            || c.kind == ComponentKind::OwnUninstaller
            || (zap && c.covered_by_cask)
            || matches!(&c.removal, ComponentRemoval::PkgForget { pkg_id } if shared_pkgs.contains(pkg_id.as_str()))
    };
    component_steps(f, selected, cfg, skip, out)
}

/// Whether to run brew with `--zap`, and why not: only when the cask's zap stanza is
/// known, has no non-path directives, every path it removes lies in a selected covered
/// component, no covered component is left out, and no zap path is shared.
fn zap_decision(
    f: &Finding,
    info: Option<&CaskInfo>,
    selected: &[usize],
) -> (bool, Option<String>) {
    if has_flag(f, FLAG_ZAP_SHARED) {
        return (
            false,
            Some("Homebrew zap skipped: it would also remove files other apps use".to_string()),
        );
    }
    let left_out = f
        .components
        .iter()
        .enumerate()
        .any(|(i, c)| c.covered_by_cask && !selected.contains(&i));
    if left_out {
        return (
            false,
            Some("Homebrew zap skipped: it would also remove items you left out".to_string()),
        );
    }
    let Some(info) = info.map(|i| &i.zap) else {
        return (
            false,
            Some("Homebrew zap skipped: its zap stanza could not be read".to_string()),
        );
    };
    let covered: Vec<&Path> = selected
        .iter()
        .map(|&i| &f.components[i])
        .filter(|c| c.covered_by_cask)
        .filter_map(|c| c.path.as_deref())
        .collect();
    let unlisted = info
        .paths
        .iter()
        .filter(|p| !covered.iter().any(|c| p.starts_with(c)))
        .count();
    if unlisted > 0 {
        return (
            false,
            Some(format!(
                "Homebrew zap skipped: it would also remove {unlisted} paths not listed here"
            )),
        );
    }
    if info.non_path_directives {
        return (
            false,
            Some(
                "Homebrew zap skipped: it would also run steps not listed here (launchctl, \
                 pkgutil or scripts)"
                    .to_string(),
            ),
        );
    }
    (true, None)
}

/// File names of the app bundles in `files` other than `bundle` that still exist
/// (outermost bundles only).
fn other_apps(files: &[PathBuf], bundle: &Path) -> Vec<String> {
    let is_app = |p: &Path| {
        p.extension()
            .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("app"))
    };
    let mut names: Vec<String> = files
        .iter()
        .filter(|p| !p.starts_with(bundle) && is_app(p))
        .filter(|p| !p.ancestors().skip(1).any(is_app))
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// A `launchctl bootout` step per selected `Bootout` component whose job is loaded now.
fn bootout_steps(f: &Finding, selected: &[usize], tools: &PlanTools, out: &mut Out) {
    for &i in selected {
        if let ComponentRemoval::Bootout { label, system } = &f.components[i].removal
            && !apple_label(label)
            && (tools.launchctl_probe)(label, *system)
        {
            out.push(Bucket::Vendor, bootout_step(f, i, label, *system));
        }
    }
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
    q.flags |= StepFlags::INTERACTIVE | StepFlags::GATE;
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

/// A selected `RunScript` component: `.scpt` → `osascript <path>`, `.sh` → `sh <path>`,
/// run as the user (`GUI_ONLY`: vendor scripts may show UI or ask for a password
/// themselves; spec §12c — never through the administrator route, the script usually
/// lives in a user-writable bundle) and a `GATE` for the finding's later steps. Any other
/// path cannot be run here and refuses the finding.
fn own_uninstaller(f: &Finding, i: usize, path: &Path, out: &mut Out) -> Result<(), String> {
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    let program = match ext.as_deref() {
        Some("scpt") => OSASCRIPT,
        Some("sh") => SH,
        _ => return Err(format!("Component {i} is not a script")),
    };
    if !Fingerprint::take(path).exists {
        out.missing += 1;
        return Ok(());
    }
    let mut s = command(
        f,
        format!("Run {}'s own uninstaller", f.title),
        vec![program.to_string(), path.to_string_lossy().into_owned()],
    );
    s.freed = None;
    s.freed_note = Some("Optional vendor step".to_string());
    s.flags |= StepFlags::GUI_ONLY | StepFlags::GATE;
    s.component = Some(i);
    s.fingerprints = vec![Fingerprint::take(path)];
    out.push(Bucket::Vendor, s);
    Ok(())
}

/// `brew uninstall --cask [--zap] <full_token>`, as the user. With `zap`, brew also
/// removes the covered leftovers: `freed` is their sum (the caller adds the bundle).
/// What the cask's `uninstall` stanza and other artifacts also do (`info`) are warnings.
fn brew_step(
    f: &Finding,
    full_token: &str,
    zap: bool,
    bundle: &Path,
    selected: &[usize],
    info: Option<&CaskInfo>,
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
    if let Some(info) = info {
        if !info.uninstall_directives.is_empty() {
            s.warnings.push(format!(
                "Homebrew will also: {}",
                info.uninstall_directives.join("; ")
            ));
        }
        let also: Vec<String> = info
            .other_app_targets
            .iter()
            .filter(|p| p.as_path() != bundle)
            .chain(&info.binaries)
            .map(|p| display(p))
            .collect();
        if !also.is_empty() {
            s.warnings
                .push(format!("Homebrew will also remove: {}", also.join(", ")));
        }
        if info.needs_admin {
            s.warnings.push(format!(
                "This cask's uninstall needs administrator rights; if it fails, run \
                 `brew uninstall --cask {full_token}` in Terminal"
            ));
        }
    }
    s
}

/// One trash step for the bundle plus every file of `files` (from the packages that are
/// not shared with another app) installed under
/// `/Applications` or the home folder that still exists; files under system folders are
/// listed as left in place.
fn pkg_step(
    f: &Finding,
    bundle: &Path,
    files: &[PathBuf],
    cfg: &Config,
    tools: &PlanTools,
) -> Step {
    let (extra, left) = pkg_paths(files, bundle, tools.home.as_deref());
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
/// inside an already chosen path; never a path with a `..` component), and the protected
/// paths left in place.
fn pkg_paths(
    files: &[PathBuf],
    bundle: &Path,
    home: Option<&Path>,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = home.filter(|h| h.is_absolute() && h.parent().is_some());
    let mut take = Vec::new();
    let mut left = Vec::new();
    for p in files {
        // `..` would escape the prefix checks below.
        if p.starts_with(bundle) || p.components().any(|c| c == std::path::Component::ParentDir) {
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

/// One step per selected component not `skip`ped: Trash → trash step; Bootout → the
/// plist's trash step (see [`bootout_steps`]); Defaults → `defaults delete` (never for a
/// [`protected_domain`], which becomes a warning); PkgForget → `pkgutil --forget`;
/// RunScript (see [`own_uninstaller`]) and None → nothing.
/// Components whose path no longer exists are left out (and counted as missing).
fn component_steps(
    f: &Finding,
    selected: &[usize],
    cfg: &Config,
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
            // Scripts are planned by `plan_app` (vendor bucket).
            ComponentRemoval::None | ComponentRemoval::RunScript => {}
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
            ComponentRemoval::Bootout { label, .. } if apple_label(label) => {
                out.warnings.push(format!(
                    "Launch job {label} is Apple's; it is never unloaded"
                ));
            }
            // The bootout itself comes from `bootout_steps`; here only the plist.
            ComponentRemoval::Bootout { .. } => match (&c.path, exists) {
                (Some(path), Some(true)) => {
                    out.push(Bucket::Trash, component_trash(f, i, c, path, cfg));
                }
                (Some(_), _) => out.missing += 1,
                _ => {}
            },
            ComponentRemoval::Defaults { domain } => {
                let (target, _) = defaults_target(c, domain);
                if protected_domain(domain) || protected_domain(&target) {
                    out.warnings
                        .push(format!("Settings domain {domain} is never deleted"));
                    continue;
                }
                if exists == Some(false) {
                    out.missing += 1;
                    continue;
                }
                out.push(Bucket::Defaults, defaults_step(f, i, c, domain));
            }
            ComponentRemoval::PkgForget { pkg_id } => {
                if !valid_pkg_id(pkg_id) {
                    out.warnings.push(format!(
                        "Package receipt id {pkg_id} is not valid; it is never forgotten"
                    ));
                    continue;
                }
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

/// A receipt id `pkgutil --forget` may be given: `[A-Za-z0-9._-]+`, not starting with `-`
/// (never an option), not `.`/`..`.
fn valid_pkg_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Apple's own launchd jobs (`com.apple.*`, any case): never booted out or trashed.
fn apple_label(label: &str) -> bool {
    label.to_ascii_lowercase().starts_with("com.apple.")
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

/// Domains (or `defaults delete` targets) Discky never deletes: options (`-g`…), the
/// global domain under any of its names, Apple's own (`com.apple.*`), a user domain
/// holding a `/`, and a path other than a direct `/Library/Preferences/<domain>`.
/// Names are compared case-insensitively, for a path by its last component.
fn protected_domain(domain: &str) -> bool {
    if domain.starts_with('/') {
        let p = Path::new(domain);
        if p.parent() != Some(Path::new(SYSTEM_PREFERENCES)) {
            return true;
        }
    } else if domain.contains('/') {
        return true;
    }
    let leaf = domain.rsplit('/').next().unwrap_or(domain).to_lowercase();
    leaf.is_empty()
        || leaf == "."
        || leaf == ".."
        || leaf.starts_with('-')
        || leaf == "nsglobaldomain"
        || leaf == "apple global domain"
        || leaf.starts_with(".globalpreferences")
        || leaf.starts_with("com.apple.")
}

/// The argument of `defaults delete` for component `c` and whether it is a system domain:
/// a domain given as a path, or a plist under `/Library/Preferences`, is addressed by
/// its path without `.plist` and deleted as root; anything else is the user domain.
fn defaults_target(c: &Component, domain: &str) -> (String, bool) {
    if domain.starts_with('/') {
        return (domain.to_string(), true);
    }
    match c.path.as_deref() {
        Some(p) if p.starts_with(SYSTEM_PREFERENCES) => {
            (p.with_extension("").to_string_lossy().into_owned(), true)
        }
        _ => (domain.to_string(), false),
    }
}

/// `defaults delete <target>` (see [`defaults_target`]); INTERACTIVE for a system domain.
fn defaults_step(f: &Finding, i: usize, c: &Component, domain: &str) -> Step {
    let (target, system) = defaults_target(c, domain);
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
    fn uninstall_summary_lists_directives_and_admin_needs() {
        let t = tempfile::tempdir().unwrap();
        let lib = t.path().join("Library");
        std::fs::create_dir_all(lib.join("LaunchDaemons")).unwrap();
        std::fs::write(lib.join("LaunchDaemons/com.x.daemon.plist"), b"").unwrap();
        let user = cask::Directive {
            quit: vec!["com.x".into()],
            launchctl: vec!["com.x.agent".into()],
            signal: vec![("KILL".into(), "com.x".into())],
            script: Some(cask::Script {
                executable: "/usr/bin/pkill".into(),
                args: vec!["X".into()],
                must_succeed: false,
                sudo: false,
            }),
            ..Default::default()
        };
        let (lines, admin) = uninstall_summary(std::slice::from_ref(&user), t.path(), &lib);
        assert_eq!(
            lines,
            [
                "quit com.x",
                "signal KILL com.x",
                "launchctl com.x.agent",
                "script /usr/bin/pkill X"
            ]
        );
        assert!(!admin);
        for d in [
            cask::Directive {
                pkgutil: vec!["com.x.pkg".into()],
                ..Default::default()
            },
            cask::Directive {
                launchctl: vec!["com.x.daemon".into()],
                ..Default::default()
            },
            cask::Directive {
                delete: vec!["/Library/Apple".into()],
                ..Default::default()
            },
            cask::Directive {
                script: Some(cask::Script {
                    sudo: true,
                    ..user.script.clone().unwrap()
                }),
                ..Default::default()
            },
        ] {
            assert!(
                uninstall_summary(std::slice::from_ref(&d), t.path(), &lib).1,
                "{d:?}"
            );
        }
    }

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

    #[test]
    fn pkg_paths_reject_parent_dir_components() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(home.join("Library")).unwrap();
        let outside = t.path().join("outside");
        std::fs::write(&outside, b"x").unwrap();
        let sneaky = home.join("Library/../../outside");
        assert!(std::fs::symlink_metadata(&sneaky).is_ok());
        let (take, left) = pkg_paths(
            &[sneaky, PathBuf::from("/Applications/../Users/x")],
            &t.path().join("Y.app"),
            Some(&home),
        );
        assert!(take.is_empty(), "{take:?}");
        assert!(left.is_empty(), "{left:?}");
    }
}
