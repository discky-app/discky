//! Full Disk Access: the probe, the Overview notice decision and the relaunch plan.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gpui_kit::App;

/// Full Disk Access state as inferred from probing protected folders.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FdaStatus {
    Granted,
    Denied,
    Unknown,
}

/// Any `PermissionDenied` means Denied, otherwise any success means Granted, else Unknown.
pub fn fda_status_from_results(mail: &io::Result<()>, safari: &io::Result<()>) -> FdaStatus {
    let denied =
        |r: &io::Result<()>| matches!(r, Err(e) if e.kind() == io::ErrorKind::PermissionDenied);
    if denied(mail) || denied(safari) {
        FdaStatus::Denied
    } else if mail.is_ok() || safari.is_ok() {
        FdaStatus::Granted
    } else {
        FdaStatus::Unknown
    }
}

/// Probes `~/Library/Mail` and `~/Library/Safari` with `read_dir` (nothing else is read).
pub fn probe_fda(home: &Path) -> FdaStatus {
    let probe = |p: PathBuf| std::fs::read_dir(p).map(|_| ());
    fda_status_from_results(
        &probe(home.join("Library/Mail")),
        &probe(home.join("Library/Safari")),
    )
}

/// Deep link to System Settings > Privacy & Security > Full Disk Access.
pub const FDA_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

/// What the Overview shows about Full Disk Access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessNotice {
    Hidden,
    Onboarding,
    Relaunch,
    Banner,
}

/// The notice for the probed status, whether a snapshot exists, whether access was seen denied
/// this session, and whether the banner was dismissed.
pub fn notice(
    fda: Option<FdaStatus>,
    has_snapshot: bool,
    saw_denied: bool,
    dismissed: bool,
) -> AccessNotice {
    match fda {
        Some(FdaStatus::Granted) if saw_denied => AccessNotice::Relaunch,
        Some(FdaStatus::Denied) if !has_snapshot => AccessNotice::Onboarding,
        Some(FdaStatus::Denied) if !dismissed => AccessNotice::Banner,
        _ => AccessNotice::Hidden,
    }
}

/// The `.app` bundle containing `exe`, when `exe` is `<x>.app/Contents/MacOS/<name>`.
pub fn bundle_root(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    let is_bundle = macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app";
    is_bundle.then(|| app.to_path_buf())
}

/// The bundle to show in Finder next to the settings pane; `None` outside a bundle.
pub fn reveal_target(exe: &Path) -> Option<PathBuf> {
    bundle_root(exe)
}

/// Opens the Full Disk Access pane and reveals Discky.app in Finder for a drag into the list.
pub fn open_fda_settings(cx: &mut App) {
    cx.open_url(FDA_SETTINGS_URL);
    let exe = std::env::current_exe().unwrap_or_default();
    if let Some(app) = reveal_target(&exe) {
        let _ = Command::new("/usr/bin/open")
            .arg("-R")
            .arg(app)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

/// How to start Discky again after it quits.
#[derive(Debug, PartialEq, Eq)]
pub enum RelaunchPlan {
    /// Reopen the `.app` bundle.
    Open(PathBuf),
    /// Run the bare executable (development builds).
    Exec(PathBuf),
    /// A removal is running; relaunching now would interrupt it.
    Busy,
}

/// The relaunch plan for `exe`; `Busy` while a removal runs.
pub fn relaunch_plan(exe: &Path, removal_running: bool) -> RelaunchPlan {
    if removal_running {
        return RelaunchPlan::Busy;
    }
    match bundle_root(exe) {
        Some(app) => RelaunchPlan::Open(app),
        None => RelaunchPlan::Exec(exe.to_path_buf()),
    }
}

/// Spawns a detached shell that waits for `pid` to exit, then starts Discky per `plan`.
pub fn relaunch(plan: &RelaunchPlan, pid: u32) -> io::Result<()> {
    let (start, path) = match plan {
        RelaunchPlan::Open(app) => ("open", app),
        RelaunchPlan::Exec(exe) => ("exec", exe),
        RelaunchPlan::Busy => return Err(io::Error::from(io::ErrorKind::WouldBlock)),
    };
    let script = format!(r#"while kill -0 "$1" 2>/dev/null; do sleep 0.1; done; {start} "$2""#);
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg("sh")
        .arg(pid.to_string())
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fda_status_from_errors() {
        let denied = || Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let missing = || Err(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(
            fda_status_from_results(&Ok(()), &denied()),
            FdaStatus::Denied
        );
        assert_eq!(
            fda_status_from_results(&denied(), &Ok(())),
            FdaStatus::Denied
        );
        assert_eq!(
            fda_status_from_results(&Ok(()), &missing()),
            FdaStatus::Granted
        );
        assert_eq!(
            fda_status_from_results(&missing(), &missing()),
            FdaStatus::Unknown
        );
    }

    #[test]
    fn unknown_access_is_silent() {
        assert_eq!(notice(None, false, false, false), AccessNotice::Hidden);
        assert_eq!(
            notice(Some(FdaStatus::Unknown), false, false, false),
            AccessNotice::Hidden
        );
        assert_eq!(
            notice(Some(FdaStatus::Granted), false, false, false),
            AccessNotice::Hidden
        );
    }

    #[test]
    fn denied_shows_onboarding_then_banner() {
        assert_eq!(
            notice(Some(FdaStatus::Denied), false, true, false),
            AccessNotice::Onboarding
        );
        assert_eq!(
            notice(Some(FdaStatus::Denied), true, true, false),
            AccessNotice::Banner
        );
        assert_eq!(
            notice(Some(FdaStatus::Denied), true, true, true),
            AccessNotice::Hidden
        );
        // Dismissing hides the banner only; onboarding has no close button.
        assert_eq!(
            notice(Some(FdaStatus::Denied), false, true, true),
            AccessNotice::Onboarding
        );
    }

    #[test]
    fn granted_after_denied_asks_to_relaunch() {
        assert_eq!(
            notice(Some(FdaStatus::Granted), false, true, false),
            AccessNotice::Relaunch
        );
        assert_eq!(
            notice(Some(FdaStatus::Granted), true, true, true),
            AccessNotice::Relaunch
        );
    }

    #[test]
    fn bundle_root_outside_a_bundle() {
        assert_eq!(
            bundle_root(Path::new("/Applications/Discky.app/Contents/MacOS/Discky")),
            Some(PathBuf::from("/Applications/Discky.app"))
        );
        assert_eq!(
            bundle_root(Path::new("/tmp/discky/target/debug/discky-app")),
            None
        );
        assert_eq!(bundle_root(Path::new("/x/Contents/MacOS/Discky")), None);
    }

    #[test]
    fn relaunch_plan_refuses_while_removal_runs() {
        let exe = Path::new("/Applications/Discky.app/Contents/MacOS/Discky");
        assert_eq!(relaunch_plan(exe, true), RelaunchPlan::Busy);
        assert_eq!(
            relaunch_plan(exe, false),
            RelaunchPlan::Open("/Applications/Discky.app".into())
        );
        assert_eq!(
            relaunch_plan(Path::new("/t/debug/discky-app"), false),
            RelaunchPlan::Exec("/t/debug/discky-app".into())
        );
    }
}
