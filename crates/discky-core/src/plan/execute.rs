//! Running a [`Plan`]: the only code in Discky that removes anything.
//!
//! Every fingerprint of every step to run is re-taken first; any change refuses the
//! whole plan. Steps then run in order, the first failure stops the plan, and every
//! executed step is appended to the history log before the next one starts. Paths are
//! only ever handed to the Trash or removed when they are listed in the step itself.
//! A window between the stale check and each action is unavoidable; the last path
//! component is still protected because every removal decides by `lstat`.
//! When a finding's `GATE` step (a `Quit`, a vendor uninstaller script) does not run
//! (skipped as interactive, or left out of `only_steps`), every later step of that
//! finding is `Skipped` too. `GUI_ONLY` steps are skipped like `INTERACTIVE` ones without
//! permission and otherwise run as the user, never through the administrator route.

use std::collections::HashMap;
use std::io::{self, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
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
/// Why a step after its finding's `Quit` that did not run is skipped: the app may still be
/// running and using what the step would remove.
const QUIT_FIRST_REASON: &str = "Needs the app quit first; run from Discky.app";
/// Why a step after another `GATE` step (a vendor script) that did not run is skipped.
const EARLIER_STEP_REASON: &str = "Needs an earlier interactive step; run from Discky.app";
/// Absolute, never looked up through `PATH`: it may show an administrator prompt.
pub const OSASCRIPT: &str = "/usr/bin/osascript";

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
    /// The step's planned `freed` when it is `Done` and actually freed it, else 0: an
    /// "already absent" step frees nothing, and a command whose target path is still
    /// present afterwards is credited what it measurably freed inside it (at most the
    /// planned `freed`).
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
#[derive(Clone)]
pub struct ExecuteOptions {
    /// Run `INTERACTIVE` and `GUI_ONLY` steps (quitting apps, Finder/administrator prompts,
    /// vendor scripts as the user) instead of
    /// skipping them.
    pub allow_interactive: bool,
    /// Run only these step indices; the rest are `NotRun`.
    pub only_steps: Option<Vec<usize>>,
    pub actor: Actor,
    /// Normally `/usr/bin/trash`.
    pub trash_bin: PathBuf,
    /// Receives a `Started` and a `Finished` event for every step that runs.
    pub on_step: Option<StepSink>,
}

impl std::fmt::Debug for ExecuteOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecuteOptions")
            .field("allow_interactive", &self.allow_interactive)
            .field("only_steps", &self.only_steps)
            .field("actor", &self.actor)
            .field("trash_bin", &self.trash_bin)
            .field("on_step", &self.on_step.as_ref().map(|_| "<sink>"))
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("plan is stale: {} changed since it was planned", path.display())]
    PlanStale { path: PathBuf },
    #[error("step index {0} is not in the plan")]
    BadStepIndex(usize),
    #[error("plan {0} is unknown or expired; plan again")]
    UnknownPlan(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Progress of a running plan, delivered to a [`StepSink`]. Steps that do not run
/// (`NotRun`) emit nothing.
#[derive(Debug, Clone)]
pub enum StepEvent {
    /// Step `index` is about to run.
    Started { index: usize },
    /// The step's final result, as it appears in the [`ExecutionReport`].
    Finished(StepResult),
}

/// Receives [`StepEvent`]s while a plan runs (called on the executing thread).
pub type StepSink = Arc<dyn Fn(StepEvent) + Send + Sync>;

/// What running one step produced, before freed accounting.
struct Outcome {
    status: StepStatus,
    output: String,
    reason: Option<String>,
    /// `Done`, but nothing was freed (already absent, or the path is still there).
    freed_nothing: bool,
    /// `Done`, crediting this many bytes instead of the step's planned `freed`
    /// (measured for a command whose target path survives).
    measured: Option<u64>,
}

impl Outcome {
    fn done(output: String) -> Outcome {
        Outcome {
            status: StepStatus::Done,
            output,
            reason: None,
            freed_nothing: false,
            measured: None,
        }
    }
    fn failed(output: String, reason: impl Into<String>) -> Outcome {
        Outcome {
            status: StepStatus::Failed,
            output,
            reason: Some(reason.into()),
            freed_nothing: false,
            measured: None,
        }
    }
    /// Not run, for `reason`.
    fn skipped(reason: &str) -> Outcome {
        Outcome {
            status: StepStatus::Skipped,
            output: String::new(),
            reason: Some(reason.to_string()),
            freed_nothing: false,
            measured: None,
        }
    }
    /// `Done` with nothing freed, for `reason`.
    fn done_freeing_nothing(output: String, reason: &str) -> Outcome {
        Outcome {
            reason: Some(reason.to_string()),
            freed_nothing: true,
            ..Outcome::done(output)
        }
    }
}

/// Run `plan` (see the module docs). `Err(BadStepIndex)` for an `only_steps` index
/// outside the plan, `Err(PlanStale)` and a log that cannot be opened are reported before
/// any side effect. A history write that fails after a step ran
/// stops the plan at that step (noted in its `reason`) and the report is still returned.
/// Each step that runs is reported to `opts.on_step` as it starts and finishes.
pub fn execute_plan(
    plan: &Plan,
    opts: &ExecuteOptions,
    paths: &DisckyPaths,
) -> Result<ExecutionReport, ExecuteError> {
    if let Some(&bad) = opts
        .only_steps
        .iter()
        .flatten()
        .find(|&&i| i >= plan.steps.len())
    {
        return Err(ExecuteError::BadStepIndex(bad));
    }
    let selected = |i: usize| opts.only_steps.as_ref().is_none_or(|o| o.contains(&i));
    let skipped = |s: &Step| needs_session(s) && !opts.allow_interactive;
    // A `GATE` step (a `Quit`, a vendor script) that will not run — skipped as
    // interactive, or left out of `only_steps` — stops every later step of its finding:
    // the app is still running, or the vendor's uninstall has not happened.
    let mut gates: HashMap<&str, (usize, &'static str)> = HashMap::new();
    for s in &plan.steps {
        if s.flags.contains(StepFlags::GATE) && (!selected(s.index) || skipped(s)) {
            let reason = if matches!(s.kind, StepKind::Quit { .. }) {
                QUIT_FIRST_REASON
            } else {
                EARLIER_STEP_REASON
            };
            let first = gates
                .entry(s.finding.0.as_str())
                .or_insert((s.index, reason));
            if s.index < first.0 {
                *first = (s.index, reason);
            }
        }
    }
    // Further quits stay allowed: quitting an app removes nothing.
    let blocked = |s: &Step| -> Option<&'static str> {
        if matches!(s.kind, StepKind::Quit { .. }) {
            return None;
        }
        gates
            .get(s.finding.0.as_str())
            .filter(|&&(g, _)| s.index > g)
            .map(|&(_, reason)| reason)
    };
    check_fresh(
        plan.steps
            .iter()
            .filter(|s| selected(s.index) && !skipped(s) && blocked(s).is_none()),
    )?;
    history::open_log(paths)?;

    let mut results = Vec::with_capacity(plan.steps.len());
    let mut stopped_at = None;
    let mut trashed_bytes = 0;
    for step in &plan.steps {
        if stopped_at.is_some() || !selected(step.index) {
            results.push(not_run(step.index));
            continue;
        }
        emit(opts, StepEvent::Started { index: step.index });
        let mut outcome = match blocked(step) {
            Some(reason) => Outcome::skipped(reason),
            None => run_step(step, opts),
        };
        let freed = match outcome.status {
            StepStatus::Done if outcome.freed_nothing => 0,
            StepStatus::Done => outcome.measured.unwrap_or_else(|| step.freed.unwrap_or(0)),
            _ => 0,
        };
        if outcome.status == StepStatus::Done && matches!(step.kind, StepKind::Trash { .. }) {
            trashed_bytes += freed;
        }
        if outcome.status == StepStatus::Failed {
            stopped_at = Some(step.index);
        }
        if let Err(e) = history::append(paths, &record(plan, step, opts.actor, &outcome, freed)) {
            let note = format!("History write failed: {e}; stopping");
            outcome.reason = Some(match outcome.reason.take() {
                Some(r) => format!("{r}; {note}"),
                None => note,
            });
            stopped_at = Some(step.index);
        }
        let result = StepResult {
            index: step.index,
            status: outcome.status,
            output: outcome.output,
            freed,
            reason: outcome.reason,
        };
        emit(opts, StepEvent::Finished(result.clone()));
        results.push(result);
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

/// Deliver `event` to the sink, if any. A panicking sink is ignored: it must not abort
/// a plan halfway through.
fn emit(opts: &ExecuteOptions, event: StepEvent) {
    if let Some(sink) = &opts.on_step {
        let _ = catch_unwind(AssertUnwindSafe(|| sink(event)));
    }
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
    // `GUI_ONLY` needs the session too, but runs as the user: only `INTERACTIVE` takes the
    // Finder / administrator routes below.
    let interactive = step.flags.contains(StepFlags::INTERACTIVE);
    if needs_session(step) && !opts.allow_interactive {
        return Outcome::skipped(INTERACTIVE_REASON);
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
        StepKind::Trash { paths } if interactive => {
            verify_gone(paths, run_osascript(paths, finder_delete_script))
        }
        StepKind::Trash { paths } => verify_gone(paths, run_trash(&opts.trash_bin, paths)),
        StepKind::Remove { paths } if interactive => {
            verify_gone(paths, run_osascript(paths, admin_rm_script))
        }
        StepKind::Remove { paths } => verify_gone(paths, run_remove(paths)),
        StepKind::Command { argv, cwd, env } => {
            let target = command_target(step, cwd.as_deref());
            let before = target.map(allocated_tree);
            let outcome = if interactive && !env.is_empty() {
                Outcome::failed(
                    String::new(),
                    "admin command cannot set environment variables",
                )
            } else if interactive {
                run_admin_command(argv, cwd.as_deref())
            } else {
                run_command(argv, cwd.as_deref(), env)
            };
            match (target, before) {
                (Some(t), Some(before)) => measure_command(step, t, before, outcome),
                _ => outcome,
            }
        }
        StepKind::OllamaDelete { url, model } => run_ollama_delete(url, model),
    }
}

/// The step needs an interactive session (`INTERACTIVE` or `GUI_ONLY`).
fn needs_session(step: &Step) -> bool {
    step.flags
        .intersects(StepFlags::INTERACTIVE | StepFlags::GUI_ONLY)
}

fn already_absent(output: String) -> Outcome {
    Outcome::done_freeing_nothing(output, "already absent")
}

/// The finding path of a command step: its fingerprinted path that is not the cwd.
fn command_target<'a>(step: &'a Step, cwd: Option<&Path>) -> Option<&'a Path> {
    step.fingerprints
        .iter()
        .map(|f| f.path.as_path())
        .find(|p| Some(*p) != cwd)
}

/// A `Done` command whose target path is gone is credited its planned `freed`. One whose
/// target survives (a cache purge that keeps its top directory) stays `Done` and is
/// credited what it measurably freed inside it: `before - after`, capped at the planned
/// `freed`.
fn measure_command(step: &Step, target: &Path, before: u64, outcome: Outcome) -> Outcome {
    if outcome.status != StepStatus::Done || is_gone(target) {
        return outcome;
    }
    let freed = before
        .saturating_sub(allocated_tree(target))
        .min(step.freed.unwrap_or(u64::MAX));
    let reason = if freed > 0 {
        format!(
            "command finished; {} freed inside {}",
            human_bytes(freed),
            target.display()
        )
    } else {
        "command finished; nothing freed".to_string()
    };
    Outcome {
        reason: Some(reason),
        measured: Some(freed),
        ..outcome
    }
}

/// Allocated bytes (`st_blocks * 512`) of `path` and everything below it, by `lstat`
/// (symlinks are counted as links, never followed). Unreadable entries count as 0.
fn allocated_tree(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        total += m.blocks() * 512;
        if m.is_dir()
            && let Ok(rd) = std::fs::read_dir(&p)
        {
            stack.extend(rd.flatten().map(|e| e.path()));
        }
    }
    total
}

/// `512 B`, `1.5 KB`, `14.0 GB` (1024-based).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
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
    let present: Vec<&PathBuf> = paths.iter().filter(|p| !is_gone(p)).collect();
    if present.is_empty() {
        return already_absent(String::new());
    }
    let mut cmd = Command::new(trash_bin);
    cmd.args(present);
    process_outcome(&mut cmd, "trash")
}

fn run_remove(paths: &[PathBuf]) -> Outcome {
    if let Err(o) = check_absolute(paths) {
        return o;
    }
    if paths.iter().all(|p| is_gone(p)) {
        return already_absent(String::new());
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

/// Trash or remove `paths` through `osascript -e <script(present paths)>`, for paths that
/// need an administrator: Finder or `do shell script` asks for the password itself.
/// Fails closed on a path that is not valid UTF-8 (a lossy conversion could name a
/// different path) and on one ending in `/` (`rm -rf dir/` follows a symlinked `dir`).
fn run_osascript(paths: &[PathBuf], script: impl Fn(&[&str]) -> String) -> Outcome {
    if let Err(o) = check_absolute(paths) {
        return o;
    }
    let slash = |p: &&PathBuf| {
        let b = p.as_os_str().as_encoded_bytes();
        b.len() > 1 && b.ends_with(b"/")
    };
    if paths.iter().any(|p| slash(&p)) {
        return Outcome::failed(String::new(), "path ends with a slash");
    }
    let mut utf8 = Vec::with_capacity(paths.len());
    for p in paths {
        match p.to_str() {
            Some(s) => utf8.push(s),
            None => {
                return Outcome::failed(
                    String::new(),
                    format!("path is not valid UTF-8: {}", p.display()),
                );
            }
        }
    }
    let present: Vec<&str> = utf8
        .into_iter()
        .filter(|p| !is_gone(Path::new(p)))
        .collect();
    if present.is_empty() {
        return already_absent(String::new());
    }
    let mut cmd = Command::new(OSASCRIPT);
    cmd.arg("-e").arg(script(&present));
    process_outcome(&mut cmd, "osascript")
}

/// `s` as the inside of an AppleScript string literal.
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `s` as one POSIX shell word, single-quoted.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// AppleScript moving `paths` to the Trash through Finder (which prompts for an
/// administrator password itself for items the user cannot move).
pub(crate) fn finder_delete_script(paths: &[&str]) -> String {
    let files: Vec<String> = paths
        .iter()
        .map(|p| format!("POSIX file \"{}\"", applescript_escape(p)))
        .collect();
    format!(
        "tell application \"Finder\" to delete {{{}}}",
        files.join(", ")
    )
}

/// AppleScript running `/bin/rm -rf <paths>` with administrator privileges (the system
/// prompts for the password). Paths are shell-quoted, then AppleScript-escaped.
pub(crate) fn admin_rm_script(paths: &[&str]) -> String {
    let words: Vec<String> = paths.iter().map(|p| shell_quote(p)).collect();
    format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(&format!("/bin/rm -rf {}", words.join(" ")))
    )
}

/// AppleScript running `argv` with administrator privileges (the system prompts for the
/// password). Each argument is one shell word — bare when it only holds characters the
/// shell never interprets, else single-quoted — and the line is AppleScript-escaped.
pub(crate) fn admin_command_script(argv: &[&str]) -> String {
    let words: Vec<String> = argv.iter().map(|a| shell_word(a)).collect();
    format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(&words.join(" "))
    )
}

/// `s` unquoted when it is non-empty and only holds `[A-Za-z0-9_@%+=:,./-]`, else
/// [`shell_quote`]d.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if plain { s.to_string() } else { shell_quote(s) }
}

/// Run an `INTERACTIVE` command step through `osascript -e <admin_command_script>`, which
/// shows the administrator prompt. Fails closed before building any script when the
/// program is not an absolute path (never looked up through `PATH` as root), when an
/// absolute-path argument ends in `/`, when an argument holds a NUL, or when a working
/// directory is given (`do shell script` would not honour it).
fn run_admin_command(argv: &[String], cwd: Option<&Path>) -> Outcome {
    let Some(program) = argv.first() else {
        return Outcome::failed(String::new(), "Empty command");
    };
    if !Path::new(program).is_absolute() {
        return Outcome::failed(
            String::new(),
            "admin command must use an absolute program path",
        );
    }
    if cwd.is_some() {
        return Outcome::failed(
            String::new(),
            "admin command cannot have a working directory",
        );
    }
    if argv
        .iter()
        .any(|a| a.len() > 1 && a.starts_with('/') && a.ends_with('/'))
    {
        return Outcome::failed(String::new(), "path ends with a slash");
    }
    if argv.iter().any(|a| a.contains('\0')) {
        return Outcome::failed(String::new(), "argument contains a NUL byte");
    }
    let words: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut cmd = Command::new(OSASCRIPT);
    cmd.arg("-e").arg(admin_command_script(&words));
    process_outcome(&mut cmd, "osascript")
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

/// Run `argv` as the user, in `cwd` when set, with `env` added to the inherited
/// environment.
fn run_command(argv: &[String], cwd: Option<&Path>, env: &[(String, String)]) -> Outcome {
    let Some((program, args)) = argv.split_first() else {
        return Outcome::failed(String::new(), "Empty command");
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    if let Some(cwd) = cwd {
        if let Err(o) = check_absolute(&[cwd.to_path_buf()]) {
            return o;
        }
        cmd.current_dir(cwd);
    }
    process_outcome(&mut cmd, program)
}

fn run_quit(bundle_id: &str) -> Outcome {
    let script = format!(
        "tell application id \"{}\" to quit",
        applescript_escape(bundle_id)
    );
    let mut cmd = Command::new(OSASCRIPT);
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
        404 => already_absent(body),
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
        reason: outcome.reason.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finder_script_quotes_paths() {
        let s = finder_delete_script(&[r#"/Library/Logs/A "B"/x\y"#]);
        assert_eq!(
            s,
            r#"tell application "Finder" to delete {POSIX file "/Library/Logs/A \"B\"/x\\y"}"#
        );
    }

    #[test]
    fn finder_script_lists_every_path() {
        let s = finder_delete_script(&["/a", "/b"]);
        assert_eq!(
            s,
            r#"tell application "Finder" to delete {POSIX file "/a", POSIX file "/b"}"#
        );
    }

    #[test]
    fn admin_rm_script_shell_and_applescript_quotes() {
        let s = admin_rm_script(&["/Library/It's \"x\""]);
        assert_eq!(
            s,
            r#"do shell script "/bin/rm -rf '/Library/It'\\''s \"x\"'" with administrator privileges"#
        );
    }

    #[test]
    fn admin_command_script_quotes_argv() {
        assert_eq!(
            admin_command_script(&["/usr/sbin/pkgutil", "--forget", "us.zoom.pkg"]),
            r#"do shell script "/usr/sbin/pkgutil --forget us.zoom.pkg" with administrator privileges"#
        );
        assert_eq!(
            admin_command_script(&["/bin/launchctl", "bootout", "it's \"x\"", ""]),
            r#"do shell script "/bin/launchctl bootout 'it'\\''s \"x\"' ''" with administrator privileges"#
        );
    }

    #[test]
    fn admin_command_needs_an_absolute_program() {
        let o = run_admin_command(&["pkgutil".to_string(), "--forget".to_string()], None);
        assert_eq!(o.status, StepStatus::Failed);
        assert_eq!(
            o.reason.as_deref(),
            Some("admin command must use an absolute program path")
        );
    }

    #[test]
    fn non_utf8_path_fails_before_any_script() {
        use std::os::unix::ffi::OsStrExt;
        let p = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
        let built = std::sync::atomic::AtomicBool::new(false);
        let o = run_osascript(&[p], |_: &[&str]| {
            built.store(true, std::sync::atomic::Ordering::SeqCst);
            String::new()
        });
        assert_eq!(o.status, StepStatus::Failed);
        assert_eq!(
            o.reason.as_deref(),
            Some("path is not valid UTF-8: /tmp/\u{fffd}")
        );
        assert!(!built.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn trailing_slash_path_fails_before_any_script() {
        let built = std::sync::atomic::AtomicBool::new(false);
        let o = run_osascript(&[PathBuf::from("/tmp/discky-x/")], |_: &[&str]| {
            built.store(true, std::sync::atomic::Ordering::SeqCst);
            String::new()
        });
        assert_eq!(o.status, StepStatus::Failed);
        assert_eq!(o.reason.as_deref(), Some("path ends with a slash"));
        assert!(!built.load(std::sync::atomic::Ordering::SeqCst));
    }
}
