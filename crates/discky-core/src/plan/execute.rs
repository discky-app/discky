//! Running a [`Plan`]: the only code in Discky that removes anything.
//!
//! Every fingerprint of every step to run is re-taken first; any change refuses the
//! whole plan. Steps then run in order, the first failure stops the plan, and every
//! executed step is appended to the history log before the next one starts. Paths are
//! only ever handed to the Trash or removed when they are listed in the step itself.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{Fingerprint, Plan, PlanId, Step, StepFlags, StepKind};
use crate::DisckyPaths;
use crate::history::{self, HistoryRecord};
use crate::index::snapshot::Actor;

/// Bytes of stdout+stderr kept per step.
const OUTPUT_TAIL: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const OLLAMA_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
const INTERACTIVE_REASON: &str = "Needs an interactive session; run from Discky.app";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Done,
    Failed,
    Skipped,
    NotRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub index: usize,
    pub status: StepStatus,
    /// Last 4 KiB of stdout+stderr.
    pub output: String,
    /// The step's planned `freed` when it is `Done`, else 0.
    pub freed: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub plan: PlanId,
    /// One per plan step, in plan order.
    pub results: Vec<StepResult>,
    pub freed_total: u64,
    /// The part of `freed_total` moved to the Trash (still on disk until emptied).
    pub trashed_bytes: u64,
    /// Index of the step that failed and stopped the plan.
    pub stopped_at: Option<usize>,
    pub log_path: PathBuf,
}

/// No `Default`: the caller must choose `actor` and `allow_interactive` deliberately.
#[derive(Debug, Clone)]
pub struct ExecuteOptions {
    pub allow_interactive: bool,
    /// Run only these step indices; the rest are `NotRun`.
    pub only_steps: Option<Vec<usize>>,
    pub actor: Actor,
    /// Normally `/usr/bin/trash`.
    pub trash_bin: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("plan is stale: {} changed since it was planned", path.display())]
    PlanStale { path: PathBuf },
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What running one step produced, before freed accounting.
struct Outcome {
    status: StepStatus,
    output: String,
    reason: Option<String>,
}

impl Outcome {
    fn done(output: String) -> Outcome {
        Outcome {
            status: StepStatus::Done,
            output,
            reason: None,
        }
    }
    fn failed(output: String, reason: impl Into<String>) -> Outcome {
        Outcome {
            status: StepStatus::Failed,
            output,
            reason: Some(reason.into()),
        }
    }
}

/// Run `plan` (see the module docs). `Err(PlanStale)` and a log that cannot be opened
/// are reported before any side effect.
pub fn execute_plan(
    plan: &Plan,
    opts: &ExecuteOptions,
    paths: &DisckyPaths,
) -> Result<ExecutionReport, ExecuteError> {
    let selected = |i: usize| opts.only_steps.as_ref().is_none_or(|o| o.contains(&i));
    check_fresh(plan.steps.iter().filter(|s| selected(s.index)))?;
    history::open_log(paths)?;

    let mut results = Vec::with_capacity(plan.steps.len());
    let mut stopped_at = None;
    let mut trashed_bytes = 0;
    for step in &plan.steps {
        if stopped_at.is_some() || !selected(step.index) {
            results.push(not_run(step.index));
            continue;
        }
        let outcome = run_step(step, opts);
        let freed = match outcome.status {
            StepStatus::Done => step.freed.unwrap_or(0),
            _ => 0,
        };
        if outcome.status == StepStatus::Done && matches!(step.kind, StepKind::Trash { .. }) {
            trashed_bytes += freed;
        }
        history::append(paths, &record(plan, step, opts.actor, &outcome, freed))?;
        if outcome.status == StepStatus::Failed {
            stopped_at = Some(step.index);
        }
        results.push(StepResult {
            index: step.index,
            status: outcome.status,
            output: outcome.output,
            freed,
            reason: outcome.reason,
        });
    }
    Ok(ExecutionReport {
        plan: plan.id.clone(),
        freed_total: results.iter().map(|r| r.freed).sum(),
        results,
        trashed_bytes,
        stopped_at,
        log_path: paths.log.clone(),
    })
}

/// The first fingerprint whose path no longer matches its planned state.
fn check_fresh<'a>(steps: impl Iterator<Item = &'a Step>) -> Result<(), ExecuteError> {
    for fp in steps.flat_map(|s| &s.fingerprints) {
        if Fingerprint::take(&fp.path) != *fp {
            return Err(ExecuteError::PlanStale {
                path: fp.path.clone(),
            });
        }
    }
    Ok(())
}

fn not_run(index: usize) -> StepResult {
    StepResult {
        index,
        status: StepStatus::NotRun,
        output: String::new(),
        freed: 0,
        reason: None,
    }
}

fn run_step(step: &Step, opts: &ExecuteOptions) -> Outcome {
    if step.flags.contains(StepFlags::INTERACTIVE) && !opts.allow_interactive {
        return Outcome {
            status: StepStatus::Skipped,
            output: String::new(),
            reason: Some(INTERACTIVE_REASON.to_string()),
        };
    }
    if step.flags.contains(StepFlags::TOOL_MISSING) {
        let reason = step
            .warnings
            .first()
            .map_or("Tool not found", String::as_str);
        return Outcome::failed(String::new(), reason);
    }
    match &step.kind {
        StepKind::Quit { bundle_id } => run_quit(bundle_id),
        StepKind::Trash { paths } => verify_gone(paths, run_trash(&opts.trash_bin, paths)),
        StepKind::Remove { paths } => verify_gone(paths, run_remove(paths)),
        StepKind::Command { argv, cwd } => run_command(argv, cwd.as_deref()),
        StepKind::OllamaDelete { url, model } => run_ollama_delete(url, model),
    }
}

/// Plan paths must be absolute: a relative one would resolve against our cwd, and one
/// starting with `-` could be read as an option by the trash binary.
fn check_absolute(paths: &[PathBuf]) -> Result<(), Outcome> {
    match paths.iter().find(|p| !p.is_absolute()) {
        Some(p) => Err(Outcome::failed(
            String::new(),
            format!("Refusing a relative path: {}", p.display()),
        )),
        None => Ok(()),
    }
}

fn run_trash(trash_bin: &Path, paths: &[PathBuf]) -> Outcome {
    if let Err(o) = check_absolute(paths) {
        return o;
    }
    let mut cmd = Command::new(trash_bin);
    cmd.args(paths);
    process_outcome(&mut cmd, "trash")
}

fn run_remove(paths: &[PathBuf]) -> Outcome {
    if let Err(o) = check_absolute(paths) {
        return o;
    }
    for p in paths {
        // `lstat`: a symlink is removed as a link, never followed.
        let res = match std::fs::symlink_metadata(p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
            Ok(_) => std::fs::remove_file(p),
        };
        if let Err(e) = res {
            return Outcome::failed(String::new(), format!("{}: {e}", p.display()));
        }
    }
    Outcome::done(String::new())
}

/// A `Done` trash/remove whose paths still exist (by `lstat`; any error other than
/// "not found" counts as still there) becomes `Failed`.
fn verify_gone(paths: &[PathBuf], outcome: Outcome) -> Outcome {
    if outcome.status != StepStatus::Done {
        return outcome;
    }
    let left: Vec<String> = paths
        .iter()
        .filter(|p| !is_gone(p))
        .map(|p| p.display().to_string())
        .collect();
    if left.is_empty() {
        return outcome;
    }
    Outcome::failed(
        outcome.output,
        format!("Still present: {}", left.join(", ")),
    )
}

/// `lstat` says not found (any other error means it may still be there).
fn is_gone(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == io::ErrorKind::NotFound)
}

fn run_command(argv: &[String], cwd: Option<&Path>) -> Outcome {
    let Some((program, args)) = argv.split_first() else {
        return Outcome::failed(String::new(), "Empty command");
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    process_outcome(&mut cmd, program)
}

fn run_quit(bundle_id: &str) -> Outcome {
    let script = format!(
        "tell application id \"{}\" to quit",
        bundle_id.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let mut cmd = Command::new("osascript");
    cmd.args(["-e", &script]);
    process_outcome(&mut cmd, "osascript")
}

fn run_ollama_delete(url: &str, model: &str) -> Outcome {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(OLLAMA_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into();
    let endpoint = format!("{}/api/delete", url.trim_end_matches('/'));
    let mut resp = match agent
        .delete(&endpoint)
        .force_send_body()
        .send_json(serde_json::json!({ "model": model }))
    {
        Ok(r) => r,
        Err(e) => return Outcome::failed(String::new(), format!("DELETE {endpoint}: {e}")),
    };
    let status = resp.status().as_u16();
    let body = tail(
        resp.body_mut()
            .read_to_string()
            .unwrap_or_default()
            .as_bytes(),
    );
    match status {
        200..=299 => Outcome::done(body),
        404 => Outcome {
            reason: Some("already absent".to_string()),
            ..Outcome::done(body)
        },
        _ => Outcome::failed(body.clone(), format!("HTTP {status}: {body}")),
    }
}

/// Run `cmd` with captured output and the 10-minute timeout: `Done` iff exit 0.
fn process_outcome(cmd: &mut Command, name: &str) -> Outcome {
    match run_captured(cmd, COMMAND_TIMEOUT) {
        Err(e) => Outcome::failed(String::new(), format!("Could not start {name}: {e}")),
        Ok(Captured::TimedOut(out)) => Outcome::failed(
            out,
            format!("timed out after {} s", COMMAND_TIMEOUT.as_secs()),
        ),
        Ok(Captured::Exited(status, out)) if status.success() => Outcome::done(out),
        Ok(Captured::Exited(status, out)) => Outcome::failed(out, format!("{name}: {status}")),
    }
}

enum Captured {
    Exited(std::process::ExitStatus, String),
    TimedOut(String),
}

/// Spawn `cmd` (stdin null, stdout/stderr captured), poll it every 100 ms and kill it
/// after `timeout`. The output is the tail of stdout followed by stderr.
fn run_captured(cmd: &mut Command, timeout: Duration) -> io::Result<Captured> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = Arc::new(Mutex::new(Vec::new()));
    let err = Arc::new(Mutex::new(Vec::new()));
    let readers = [
        child.stdout.take().map(|s| drain(s, Arc::clone(&out))),
        child.stderr.take().map(|s| drain(s, Arc::clone(&err))),
    ];
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(POLL);
    };
    // A background grandchild may keep a pipe open: wait for the readers only briefly.
    let deadline = Instant::now() + Duration::from_secs(2);
    for r in readers.into_iter().flatten() {
        while !r.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let mut all = out.lock().map(|b| b.clone()).unwrap_or_default();
    all.extend(err.lock().map(|b| b.clone()).unwrap_or_default());
    let output = tail(&all);
    Ok(match status {
        Some(s) => Captured::Exited(s, output),
        None => Captured::TimedOut(output),
    })
}

/// Read `src` to the end on a thread, keeping only its last `OUTPUT_TAIL` bytes in `buf`.
fn drain(mut src: impl Read + Send + 'static, buf: Arc<Mutex<Vec<u8>>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = src.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let Ok(mut b) = buf.lock() else { break };
            b.extend_from_slice(&chunk[..n]);
            let excess = b.len().saturating_sub(OUTPUT_TAIL);
            b.drain(..excess);
        }
    })
}

/// The last `OUTPUT_TAIL` bytes of `bytes` as (lossy) UTF-8.
fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(OUTPUT_TAIL);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn record(plan: &Plan, step: &Step, actor: Actor, outcome: &Outcome, freed: u64) -> HistoryRecord {
    let (kind, paths, argv) = match &step.kind {
        StepKind::Quit { .. } => ("quit", Vec::new(), None),
        StepKind::Trash { paths } => ("trash", paths.clone(), None),
        StepKind::Remove { paths } => ("remove", paths.clone(), None),
        StepKind::Command { argv, .. } => (
            "command",
            step.fingerprints.iter().map(|f| f.path.clone()).collect(),
            Some(argv.clone()),
        ),
        StepKind::OllamaDelete { .. } => ("ollama_delete", Vec::new(), None),
    };
    // Paths that existed at planning and a trash step made disappear — also when the
    // step then failed on a later path.
    let trash_paths = match &step.kind {
        StepKind::Trash { .. } if outcome.status != StepStatus::Skipped => {
            let gone: Vec<PathBuf> = step
                .fingerprints
                .iter()
                .filter(|f| f.exists && is_gone(&f.path))
                .map(|f| f.path.clone())
                .collect();
            expected_trash_paths(&gone)
        }
        _ => Vec::new(),
    };
    HistoryRecord {
        ts: super::now_secs(),
        actor,
        plan: plan.id.clone(),
        step: step.index,
        kind: kind.to_string(),
        paths,
        argv,
        status: outcome.status,
        freed,
        output_tail: outcome.output.clone(),
        trash_paths,
    }
}

/// `~/.Trash/<basename>` per path (best effort: the Trash may rename on collision).
fn expected_trash_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
        return Vec::new();
    };
    let trash = PathBuf::from(home).join(".Trash");
    paths
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| trash.join(n))
        .collect()
}
