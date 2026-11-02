//! Background scan jobs: one `std::thread` per scan walks the roots, categorizes, saves the
//! snapshot and swaps it into the engine's [`Current`] state.

use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::config::Thresholds;
use crate::findings::Categorizer;
use crate::fs::walk::{Progress, ScanOptions, walk};
use crate::index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotMeta};
use crate::rules::RuleSet;

const TMUTIL_TIMEOUT: Duration = Duration::from_secs(2);

/// Identifies one scan job: 8 hex digits derived from the start time and a counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScanId(pub String);

impl ScanId {
    fn generate() -> ScanId {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        ScanId(format!(
            "{:08x}",
            xxh3_64(format!("{nanos}:{n}").as_bytes()) as u32
        ))
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanStatus {
    Running {
        progress: Progress,
        /// Unix seconds.
        started_at: i64,
    },
    Done {
        /// Unix seconds.
        finished_at: i64,
        duration_ms: u64,
        node_count: u32,
        findings: usize,
        no_access: usize,
        /// Whether the scan measured exact private sizes (local snapshots were present);
        /// see `Overview::exact_private_size`.
        exact_private_size: bool,
    },
    Failed {
        error: String,
    },
    Unknown,
}

/// What the engine currently serves; replaced as a whole when a scan finishes.
#[derive(Debug, Default)]
pub(crate) struct Current {
    pub snapshot: Option<Arc<Snapshot>>,
    /// `None` when unknown (no snapshot, or one loaded from disk).
    pub exact_private_size: Option<bool>,
}

/// Everything a scan needs, copied out of the engine at start.
pub(crate) struct ScanRequest {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<String>,
    pub thresholds: Thresholds,
    pub rules: Arc<RuleSet>,
    pub actor: Actor,
    pub snapshot_path: PathBuf,
}

/// A started scan: live progress while running, its final status once finished.
pub(crate) struct ScanJob {
    started_at: i64,
    progress: Arc<Mutex<Progress>>,
    outcome: Arc<Mutex<Option<ScanStatus>>>,
}

impl ScanJob {
    pub fn status(&self) -> ScanStatus {
        if let Some(done) = lock(&self.outcome).clone() {
            return done;
        }
        ScanStatus::Running {
            progress: lock(&self.progress).clone(),
            started_at: self.started_at,
        }
    }

    pub fn is_running(&self) -> bool {
        lock(&self.outcome).is_none()
    }
}

/// Start `req` on a new thread; it publishes its snapshot into `current` when done.
pub(crate) fn spawn(req: ScanRequest, current: Arc<RwLock<Current>>) -> (ScanId, ScanJob) {
    let job = ScanJob {
        started_at: unix_now(),
        progress: Arc::default(),
        outcome: Arc::default(),
    };
    let progress = Arc::clone(&job.progress);
    let outcome = Arc::clone(&job.outcome);
    std::thread::spawn(move || {
        let status = catch_unwind(AssertUnwindSafe(|| run(&req, &progress, &current)))
            .unwrap_or_else(|panic| ScanStatus::Failed {
                error: format!("Scan panicked: {}", panic_message(panic.as_ref())),
            });
        *lock(&outcome) = Some(status);
    });
    (ScanId::generate(), job)
}

fn run(req: &ScanRequest, progress: &Mutex<Progress>, current: &RwLock<Current>) -> ScanStatus {
    let started = Instant::now();
    let exclude = match build_globs(&req.exclude) {
        Ok(g) => g,
        Err(error) => return ScanStatus::Failed { error },
    };
    let exact = local_snapshots_exist();
    let opts = ScanOptions {
        roots: req.roots.clone(),
        exclude,
        threads: 0,
        exact_private_size: exact,
    };
    let index = walk(&opts, &|p| *lock(progress) = p.clone());
    let findings = Categorizer {
        index: &index,
        rules: &req.rules,
        thresholds: &req.thresholds,
    }
    .run();
    let snapshot = Snapshot {
        meta: SnapshotMeta {
            format_version: SNAPSHOT_FORMAT,
            created_at: unix_now(),
            actor: req.actor,
            roots: req.roots.clone(),
            no_access: index.errors.iter().map(|e| e.path.clone()).collect(),
            node_count: index.len() as u32,
        },
        index,
        findings,
    };
    let saved = snapshot.save(&req.snapshot_path);
    let done = ScanStatus::Done {
        finished_at: unix_now(),
        duration_ms: started.elapsed().as_millis() as u64,
        node_count: snapshot.meta.node_count,
        findings: snapshot.findings.len(),
        no_access: snapshot.meta.no_access.len(),
        exact_private_size: exact,
    };
    *current.write().unwrap_or_else(|e| e.into_inner()) = Current {
        snapshot: Some(Arc::new(snapshot)),
        exact_private_size: Some(exact),
    };
    match saved {
        Ok(()) => done,
        Err(e) => ScanStatus::Failed {
            error: format!(
                "Scan finished but saving the snapshot to {} failed: {e}",
                req.snapshot_path.display()
            ),
        },
    }
}

fn build_globs(patterns: &[String]) -> Result<GlobSet, String> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p).map_err(|e| format!("Invalid exclude pattern {p:?}: {e}"))?);
    }
    b.build()
        .map_err(|e| format!("Invalid exclude patterns: {e}"))
}

/// Whether Time Machine local snapshots exist on `/` (`tmutil listlocalsnapshots /`, at
/// most 2 s). Any failure counts as "no".
fn local_snapshots_exist() -> bool {
    let Ok(mut child) = Command::new("tmutil")
        .args(["listlocalsnapshots", "/"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + TMUTIL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
    let mut out = String::new();
    child
        .stdout
        .take()
        .is_some_and(|mut s| s.read_to_string(&mut out).is_ok())
        && lists_time_machine_snapshot(&out)
}

fn lists_time_machine_snapshot(tmutil_stdout: &str) -> bool {
    tmutil_stdout
        .lines()
        .any(|l| l.trim_start().starts_with("com.apple.TimeMachine"))
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

/// Lock ignoring poisoning: the guarded values stay consistent (whole-value writes).
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_time_machine_snapshot_lines() {
        let out = "Snapshots for disk /:\ncom.apple.TimeMachine.2026-11-02-101010.local\n";
        assert!(lists_time_machine_snapshot(out));
        assert!(!lists_time_machine_snapshot("Snapshots for disk /:\n"));
        assert!(!lists_time_machine_snapshot("com.apple.os.update-ABC\n"));
    }

    #[test]
    fn invalid_exclude_glob_is_an_error() {
        assert!(build_globs(&["[".into()]).is_err());
        assert!(build_globs(&["**/node_modules".into()]).is_ok());
    }
}
