//! [`Engine`]: the one object the GUI and the MCP server hold. It owns the configuration,
//! the current snapshot, scan jobs and recent plans, and wraps the query, plan and
//! execution modules.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{Config, ConfigError};
use crate::findings::{Finding, FindingId};
use crate::history::{self, HistoryRecord};
use crate::index::snapshot::{Actor, Snapshot, SnapshotError, SnapshotMeta};
use crate::paths::DisckyPaths;
use crate::plan::execute::{
    self, ExecuteError, ExecuteOptions, ExecutionReport, StepSink, StepStatus,
};
use crate::plan::{Fingerprint, Plan, PlanId, StepKind, plan_removal};
use crate::query::{self, Overview, QueryError, SearchQuery, TreeEntry};
use crate::rules::{Category, RuleSet, SafetyLabel};
use crate::scan::{self, Current, ScanId, ScanJob, ScanRequest, ScanSink, ScanStatus, lock};

/// Plans kept for [`Engine::get_plan`].
const PLAN_HISTORY: usize = 20;
const INSPECT_CHILDREN: usize = 20;
const WAIT_POLL: Duration = Duration::from_millis(100);
const TRASH_BIN: &str = "/usr/bin/trash";

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("no snapshot yet: run a scan first")]
    NoSnapshot,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Query(#[from] QueryError),
}

/// Everything known about one finding or path.
#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub finding: Option<Finding>,
    pub entry: Option<TreeEntry>,
    /// Largest children first, at most 20.
    pub children: Vec<TreeEntry>,
    /// `(title, explain)` of the matching rule, or the finding's own for synthetic rules.
    pub rule: Option<(String, String)>,
    pub owner_app: Option<String>,
    pub in_snapshot: bool,
}

/// What [`Engine::open_with`] needs from the outside world. Build it explicitly (the GUI,
/// tests) or with [`EngineOptions::resolve`] (the MCP server).
#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub paths: DisckyPaths,
    pub actor: Actor,
    /// The program Trash steps run, normally `/usr/bin/trash`.
    pub trash_bin: PathBuf,
}

impl EngineOptions {
    /// [`DisckyPaths::resolve`] (reads `DISCKY_HOME`), and `DISCKY_TRASH_BIN` or
    /// `/usr/bin/trash` for the trash binary. The `DISCKY_TRASH_BIN` override is for tests
    /// and development only (a fake that keeps test runs out of the real Trash).
    pub fn resolve(actor: Actor) -> EngineOptions {
        EngineOptions {
            paths: DisckyPaths::resolve(),
            actor,
            trash_bin: std::env::var_os("DISCKY_TRASH_BIN")
                .map_or_else(|| PathBuf::from(TRASH_BIN), PathBuf::from),
        }
    }
}

/// How to run a plan with [`Engine::execute_plan`]. No `Default`: the caller chooses
/// `allow_interactive` deliberately.
#[derive(Clone)]
pub struct ExecuteRequest {
    pub allow_interactive: bool,
    /// Run only these step indices; the rest are `NotRun`.
    pub only_steps: Option<Vec<usize>>,
    /// Receives step progress while the plan runs.
    pub on_step: Option<StepSink>,
}

pub struct Engine {
    paths: DisckyPaths,
    config: RwLock<Config>,
    rules: Arc<RuleSet>,
    actor: Actor,
    trash_bin: PathBuf,
    current: Arc<RwLock<Current>>,
    scans: Mutex<HashMap<ScanId, ScanJob>>,
    plans: Mutex<VecDeque<Plan>>,
    last_error: Mutex<Option<String>>,
}

fn _assert_send_sync<T: Send + Sync>() {}
const _: fn() = _assert_send_sync::<Engine>;

impl Engine {
    /// [`Engine::open_with`] with [`EngineOptions::resolve`] (reads `DISCKY_HOME` and
    /// `DISCKY_TRASH_BIN`).
    pub fn open(actor: Actor) -> Result<Engine, EngineError> {
        Engine::open_with(EngineOptions::resolve(actor))
    }

    /// Load the config and the snapshot if one is usable, from `opts.paths`. A missing or
    /// incompatible snapshot is ignored; any other load error is ignored too but kept in
    /// [`Engine::last_error`].
    pub fn open_with(opts: EngineOptions) -> Result<Engine, EngineError> {
        let EngineOptions {
            paths,
            actor,
            trash_bin,
        } = opts;
        let config = Config::load(&paths)?;
        let mut last_error = None;
        let snapshot = match Snapshot::load(&paths.snapshot) {
            Ok(s) => Some(Arc::new(s)),
            Err(SnapshotError::Incompatible) => None,
            Err(SnapshotError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                last_error = Some(format!(
                    "Ignoring snapshot {}: {e}",
                    paths.snapshot.display()
                ));
                None
            }
        };
        Ok(Engine {
            paths,
            config: RwLock::new(config),
            rules: Arc::new(RuleSet::builtin()),
            actor,
            trash_bin,
            current: Arc::new(RwLock::new(Current { snapshot })),
            scans: Mutex::default(),
            plans: Mutex::default(),
            last_error: Mutex::new(last_error),
        })
    }

    /// Where this engine keeps its config, snapshot and log.
    pub fn paths(&self) -> &DisckyPaths {
        &self.paths
    }

    /// The most recent non-fatal error (snapshot load, history read), if any.
    pub fn last_error(&self) -> Option<String> {
        lock(&self.last_error).clone()
    }

    pub fn config(&self) -> Config {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Save `c` to disk, then make it current.
    pub fn set_config(&self, c: Config) -> Result<(), ConfigError> {
        c.save(&self.paths)?;
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = c;
        Ok(())
    }

    /// Re-read config.toml from disk and make it current, writing nothing. For a
    /// long-lived process (the MCP server) while Discky.app edits the file. On error the
    /// current config is kept.
    pub fn reload_config(&self) -> Result<(), ConfigError> {
        let c = Config::load(&self.paths)?;
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = c;
        Ok(())
    }

    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.read_current().snapshot.clone()
    }

    /// The header of the snapshot file on disk; `None` if it is missing, unreadable or
    /// incompatible. Cheap: the body is not read.
    pub fn snapshot_file_meta(&self) -> Option<SnapshotMeta> {
        Snapshot::peek_meta(&self.paths.snapshot).ok()
    }

    /// Load the snapshot file if its `created_at` is newer than the in-memory snapshot's
    /// (or there is none), e.g. after the other process scanned. `Ok(true)` when it
    /// replaced the current snapshot; `Ok(false)` when the file is missing or not newer,
    /// or a scan of this engine published meanwhile.
    pub fn reload_snapshot(&self) -> Result<bool, SnapshotError> {
        let old = self.snapshot();
        let newer = |created_at: i64| old.as_ref().is_none_or(|o| created_at > o.meta.created_at);
        match Snapshot::peek_meta(&self.paths.snapshot) {
            Ok(meta) if newer(meta.created_at) => {}
            Ok(_) => return Ok(false),
            Err(SnapshotError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        let loaded = Snapshot::load(&self.paths.snapshot)?;
        if !newer(loaded.meta.created_at) {
            return Ok(false);
        }
        let mut current = self.current.write().unwrap_or_else(|e| e.into_inner());
        // A scan that published meanwhile is fresher: keep it.
        let unchanged = match (&current.snapshot, &old) {
            (Some(now), Some(old)) => Arc::ptr_eq(now, old),
            (None, None) => true,
            _ => false,
        };
        if !unchanged {
            return Ok(false);
        }
        current.snapshot = Some(Arc::new(loaded));
        Ok(true)
    }

    /// [`Engine::start_scan_with`] without a sink.
    pub fn start_scan(&self, roots: Option<Vec<PathBuf>>) -> ScanId {
        self.start_scan_with(roots, None)
    }

    /// Start a scan of `roots` (default: the configured roots) on a background thread.
    /// While a scan is running, joins it instead: returns its id and `roots` is ignored.
    /// `sink` gets every `Progress` (at most every 50 ms) and exactly one `Finished`;
    /// joining a running scan delivers its current `Progress` to `sink` immediately.
    /// The `Finished` is sent just after the status turns terminal, so it may arrive
    /// shortly after [`Engine::scan_status`] / [`Engine::wait_scan`] report the end: wait
    /// for the `Finished` itself, not for the status, before treating the events as complete.
    pub fn start_scan_with(&self, roots: Option<Vec<PathBuf>>, sink: Option<ScanSink>) -> ScanId {
        let mut scans = lock(&self.scans);
        if let Some((id, job)) = scans.iter().find(|(_, j)| j.is_running()) {
            let (id, job) = (id.clone(), job.clone());
            drop(scans);
            if let Some(sink) = sink {
                job.join(sink);
            }
            return id;
        }
        let config = self.config();
        let req = ScanRequest {
            roots: roots.unwrap_or(config.scan.roots),
            exclude: config.scan.exclude,
            thresholds: config.thresholds,
            rules: Arc::clone(&self.rules),
            actor: self.actor,
            snapshot_path: self.paths.snapshot.clone(),
        };
        let (id, job) = scan::spawn(req, Arc::clone(&self.current), sink);
        scans.insert(id.clone(), job);
        id
    }

    /// True if the scan `id` was running and is now asked to stop: its status becomes
    /// `Cancelled` and no snapshot is written. False for an unknown or finished scan, or
    /// one already saving its snapshot.
    pub fn cancel_scan(&self, id: &ScanId) -> bool {
        let job = lock(&self.scans).get(id).cloned();
        job.is_some_and(|j| j.request_cancel())
    }

    pub fn scan_status(&self, id: &ScanId) -> ScanStatus {
        lock(&self.scans)
            .get(id)
            .map_or(ScanStatus::Unknown, ScanJob::status)
    }

    /// Poll every 100 ms until the scan is no longer running or `timeout` elapses; returns
    /// the last status seen.
    pub fn wait_scan(&self, id: &ScanId, timeout: Duration) -> ScanStatus {
        let deadline = Instant::now() + timeout;
        loop {
            let status = self.scan_status(id);
            if !matches!(status, ScanStatus::Running { .. }) || Instant::now() >= deadline {
                return status;
            }
            std::thread::sleep(WAIT_POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    pub fn overview(&self) -> Overview {
        query::disk_overview(self.snapshot().as_deref())
    }

    /// [`query::findings_in`] over the current snapshot, cloned; empty without one.
    pub fn findings(
        &self,
        category: Option<Category>,
        label: Option<SafetyLabel>,
        min_allocated: u64,
        older_than_days: Option<u32>,
        offset: usize,
        limit: usize,
    ) -> (Vec<Finding>, usize) {
        let Some(snap) = self.snapshot() else {
            return (Vec::new(), 0);
        };
        let (page, total) = query::findings_in(
            &snap,
            category,
            label,
            min_allocated,
            older_than_days,
            offset,
            limit,
        );
        (page.into_iter().cloned().collect(), total)
    }

    pub fn tree(&self, path: &Path, limit: usize) -> Result<Vec<TreeEntry>, EngineError> {
        let snap = self.snapshot().ok_or(EngineError::NoSnapshot)?;
        Ok(query::tree(&snap, path, limit)?)
    }

    pub fn search(&self, q: &SearchQuery) -> Result<Vec<TreeEntry>, EngineError> {
        let snap = self.snapshot().ok_or(EngineError::NoSnapshot)?;
        Ok(query::search(&snap, q))
    }

    /// Resolve `target` as a finding id, else an absolute path in the snapshot, else a
    /// finding title (case-insensitive). `None` only without a snapshot; a target that
    /// resolves to nothing (e.g. a finding removed since the scan) gives an empty
    /// inspection with `in_snapshot: false`.
    pub fn inspect(&self, target: &str) -> Option<Inspection> {
        let snap = self.snapshot()?;
        let index = &snap.index;
        let by_title = || {
            snap.findings
                .iter()
                .find(|f| f.title.to_lowercase() == target.to_lowercase())
        };
        let (finding, path) = if let Some(f) = snap.findings.iter().find(|f| f.id.0 == target) {
            (Some(f), f.path.clone())
        } else if let Some(id) = Path::new(target)
            .is_absolute()
            .then(|| index.find(Path::new(target)))
            .flatten()
        {
            let f = snap
                .findings
                .iter()
                .find(|f| f.node == Some(id) || f.path.as_deref() == Some(Path::new(target)));
            (f, Some(PathBuf::from(target)))
        } else {
            match by_title() {
                Some(f) => (Some(f), f.path.clone()),
                None => (None, None),
            }
        };

        let node = path.as_deref().and_then(|p| index.find(p));
        let (entry, children) = match (node, path.as_deref()) {
            (Some(_), Some(p)) => (
                tree_entry(&snap, p),
                query::tree(&snap, p, INSPECT_CHILDREN).unwrap_or_default(),
            ),
            _ => (None, Vec::new()),
        };
        let rule = finding.map(|f| match self.rules.get(&f.rule_id) {
            Some(r) => (r.title.clone(), r.explain.clone()),
            None => (f.title.clone(), f.explain.clone()),
        });
        let owner_app = finding
            .filter(|f| f.category == Category::AppCaches)
            .map(|f| f.title.clone());
        Some(Inspection {
            finding: finding.cloned(),
            entry,
            children,
            rule,
            owner_app,
            in_snapshot: node.is_some(),
        })
    }

    /// Plan the removal of the findings `ids` (a repeated id counts once, at its first
    /// position); ids not in the current snapshot are listed in `Plan::skipped`. The plan
    /// is kept for [`Engine::get_plan`].
    pub fn plan(&self, ids: &[String]) -> Result<Plan, EngineError> {
        let snap = self.snapshot().ok_or(EngineError::NoSnapshot)?;
        let mut found = Vec::new();
        let mut unknown = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for id in ids.iter().filter(|id| seen.insert(id.as_str())) {
            match snap.findings.iter().find(|f| &f.id.0 == id) {
                Some(f) => found.push(f),
                None => unknown.push((
                    FindingId(id.clone()),
                    "Unknown finding id (rescan?)".to_string(),
                )),
            }
        }
        let mut plan = plan_removal(&found, &self.config());
        plan.skipped.extend(unknown);
        let mut plans = lock(&self.plans);
        plans.push_back(plan.clone());
        while plans.len() > PLAN_HISTORY {
            plans.pop_front();
        }
        Ok(plan)
    }

    pub fn get_plan(&self, id: &PlanId) -> Option<Plan> {
        lock(&self.plans).iter().find(|p| &p.id == id).cloned()
    }

    /// Run the plan `id` made by [`Engine::plan`] (one of the last 20), then drop from the
    /// in-memory snapshot the findings of `Done` steps whose paths are gone, and of `Done`
    /// Ollama deletes. The index and the snapshot file are left as they are; the next scan
    /// brings both up to date. `Err(UnknownPlan)` when `id` is not a kept plan: only plans
    /// this engine made can run. Trash steps run [`EngineOptions::trash_bin`].
    pub fn execute_plan(
        &self,
        id: &PlanId,
        req: ExecuteRequest,
    ) -> Result<ExecutionReport, ExecuteError> {
        let plan = self
            .get_plan(id)
            .ok_or_else(|| ExecuteError::UnknownPlan(id.0.clone()))?;
        let opts = ExecuteOptions {
            allow_interactive: req.allow_interactive,
            only_steps: req.only_steps,
            actor: self.actor,
            trash_bin: self.trash_bin.clone(),
            on_step: req.on_step,
        };
        let report = execute::execute_plan(&plan, &opts, &self.paths)?;
        let done: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.status == StepStatus::Done)
            .filter_map(|r| plan.steps.iter().find(|s| s.index == r.index))
            .collect();
        self.forget_removed(&done);
        Ok(report)
    }

    /// Newest first; empty (with [`Engine::last_error`] set) if the log cannot be read.
    pub fn history(&self, limit: usize) -> Vec<HistoryRecord> {
        history::read(&self.paths, limit).unwrap_or_else(|e| {
            self.set_error(format!("Cannot read {}: {e}", self.paths.log.display()));
            Vec::new()
        })
    }

    /// Trashed paths still in the Trash, with their sizes; empty (with
    /// [`Engine::last_error`] set) if the log cannot be read.
    pub fn in_trash(&self) -> Vec<(PathBuf, u64)> {
        history::in_trash(&self.paths).unwrap_or_else(|e| {
            self.set_error(format!("Cannot read {}: {e}", self.paths.log.display()));
            Vec::new()
        })
    }

    /// Publish a snapshot without the findings of `done` steps whose paths are gone, and
    /// of `done` Ollama deletes. The filtering runs without holding the lock; the new
    /// snapshot shares the old index.
    fn forget_removed(&self, done: &[&crate::plan::Step]) {
        let Some(old) = self.snapshot() else {
            return;
        };
        let gone = |f: &Finding| {
            done.iter().any(|s| {
                s.finding == f.id
                    && (matches!(s.kind, StepKind::OllamaDelete { .. }) || {
                        let paths: Vec<&Path> = match &f.path {
                            Some(p) => vec![p.as_path()],
                            None => s.fingerprints.iter().map(|fp| fp.path.as_path()).collect(),
                        };
                        !paths.is_empty() && paths.iter().all(|p| !Fingerprint::take(p).exists)
                    })
            })
        };
        let kept: Vec<&Finding> = old.findings.iter().filter(|f| !gone(f)).collect();
        if kept.len() == old.findings.len() {
            return;
        }
        let trimmed = Arc::new(Snapshot {
            meta: old.meta.clone(),
            index: Arc::clone(&old.index),
            findings: kept.into_iter().cloned().collect(),
        });
        let mut current = self.current.write().unwrap_or_else(|e| e.into_inner());
        // A scan that published meanwhile is fresher: keep it.
        if current
            .snapshot
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, &old))
        {
            current.snapshot = Some(trimmed);
        }
    }

    fn read_current(&self) -> std::sync::RwLockReadGuard<'_, Current> {
        self.current.read().unwrap_or_else(|e| e.into_inner())
    }

    fn set_error(&self, msg: String) {
        *lock(&self.last_error) = Some(msg);
    }
}

/// The [`TreeEntry`] for `path` itself, taken from its parent's listing (or, for a scan
/// root, from a search below it).
fn tree_entry(snap: &Snapshot, path: &Path) -> Option<TreeEntry> {
    let from_parent = path
        .parent()
        .filter(|p| snap.index.find(p).is_some())
        .and_then(|p| query::tree(snap, p, usize::MAX).ok())
        .and_then(|es| es.into_iter().find(|e| e.path == path));
    from_parent.or_else(|| {
        let q = SearchQuery {
            under: Some(path.to_path_buf()),
            limit: 1,
            ..SearchQuery::default()
        };
        query::search(snap, &q).into_iter().find(|e| e.path == path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Removal;
    use crate::fs::walk::{ScanOptions, walk};
    use crate::index::snapshot::{SNAPSHOT_FORMAT, SnapshotMeta};
    use crate::plan::{Step, StepFlags};

    fn ollama_finding(id: &str) -> Finding {
        Finding {
            id: FindingId(id.into()),
            category: Category::Models,
            title: id.into(),
            subtitle: None,
            path: None,
            node: None,
            allocated: 1,
            logical: 1,
            freed_if_deleted: 1,
            modified: None,
            label: SafetyLabel::AppData,
            rule_id: "ollama-models".into(),
            explain: String::new(),
            removal: Removal::OllamaDelete { model: id.into() },
            flags: vec![],
        }
    }

    #[test]
    fn done_ollama_deletes_are_forgotten() {
        let d = tempfile::tempdir().unwrap();
        let index = walk(
            &ScanOptions {
                roots: vec![d.path().into()],
                exclude: globset::GlobSet::empty(),
                threads: 0,
                exact_private_size: false,
                cancel: None,
            },
            &|_| {},
        );
        let snapshot = Snapshot {
            meta: SnapshotMeta {
                format_version: SNAPSHOT_FORMAT,
                created_at: 1,
                actor: Actor::Mcp,
                roots: vec![d.path().into()],
                no_access: vec![],
                node_count: 0,
                exact_private_size: false,
            },
            index: Arc::new(index),
            findings: vec![ollama_finding("a:1b"), ollama_finding("b:1b")],
        };
        let engine = Engine {
            paths: DisckyPaths {
                config: d.path().join("config.toml"),
                snapshot: d.path().join("snapshot.bin"),
                log: d.path().join("removals.log"),
            },
            config: RwLock::new(Config::default()),
            rules: Arc::new(RuleSet::builtin()),
            actor: Actor::Mcp,
            trash_bin: PathBuf::from(TRASH_BIN),
            current: Arc::new(RwLock::new(Current {
                snapshot: Some(Arc::new(snapshot)),
            })),
            scans: Mutex::default(),
            plans: Mutex::default(),
            last_error: Mutex::default(),
        };
        let step = Step {
            index: 0,
            finding: FindingId("a:1b".into()),
            description: String::new(),
            kind: StepKind::OllamaDelete {
                url: "http://127.0.0.1:9".into(),
                model: "a:1b".into(),
            },
            freed: Some(1),
            freed_note: None,
            flags: StepFlags::empty(),
            warnings: vec![],
            fingerprints: vec![],
        };
        engine.forget_removed(&[&step]);
        let left: Vec<_> = engine
            .snapshot()
            .unwrap()
            .findings
            .iter()
            .map(|f| f.id.0.clone())
            .collect();
        assert_eq!(left, ["b:1b"]);
    }
}
