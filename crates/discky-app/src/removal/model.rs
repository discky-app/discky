//! The removal dialog's state, free of GPUI: the planned steps as rows, their live
//! statuses while the plan runs, and the result.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use discky_core::findings::{Finding, FindingId};
use discky_core::plan::execute::{
    ExecuteError, ExecutionReport, StepEvent, StepResult, StepStatus,
};
use discky_core::plan::{Plan, PlanId, Step, StepFlags, StepKind};
use discky_core::{Config, PlanItem, RemovalMode};

use crate::format;
use crate::inspector::command_text_for;

/// Where the dialog is in its life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// `Engine::plan` is running.
    Planning,
    /// The plan is shown; Run is available when it has steps.
    Ready,
    /// The plan is executing; `current` is the step that started last.
    Running { current: Option<usize> },
    /// The plan ran (completely or up to a failed step).
    Finished(Summary),
    /// The executor refused: `path` changed since planning.
    Stale { path: PathBuf },
    /// The executor no longer knows the plan (it was dropped from the engine's recent
    /// plans): Re-plan, like Stale.
    Expired,
    /// Planning or execution failed for another reason.
    Error(String),
}

/// One planned step as the dialog shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepRow {
    pub index: usize,
    /// "<finding title> → <component title>" for a step that acts on one component.
    pub component: Option<String>,
    pub description: String,
    /// The shell form of the step (see `inspector::command_text_for`).
    pub command: String,
    /// Planned bytes; after the step finished, what it actually freed.
    pub freed: Option<u64>,
    /// Muted lines under the row: flags, the freed note, warnings.
    pub notes: Vec<String>,
    pub status: RowStatus,
    /// The step's stdout+stderr tail, once finished.
    pub output: String,
    /// Why the step failed or was skipped.
    pub reason: Option<String>,
}

/// A row's live status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowStatus {
    Pending,
    Running,
    Done,
    Failed,
    Skipped,
    NotRun,
}

/// What a finished run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub freed: u64,
    /// The part of `freed` moved to the Trash.
    pub trashed: u64,
    /// The step that failed and stopped the plan.
    pub stopped_at: Option<usize>,
    /// The removal log.
    pub log: PathBuf,
}

/// The removal dialog's model.
#[derive(Clone, Debug)]
pub struct RemovalModel {
    /// What the dialog was opened for, with each finding's component selection (planned
    /// again on Re-plan).
    pub items: Vec<PlanItem>,
    /// The finding ids of `items`, or of the plan's planned and skipped findings.
    pub ids: Vec<String>,
    pub plan: Option<Plan>,
    pub rows: Vec<StepRow>,
    pub phase: Phase,
    /// `removal.mode` is Permanent.
    pub permanent_mode: bool,
    /// `removal.remind_trash`: offer "Empty Trash" after a run that trashed something.
    pub remind_trash: bool,
    /// The step indices the current run executes (`None` = all; see [`run_only_steps`]).
    pub run_only: Option<Vec<usize>>,
}

impl RemovalModel {
    /// A dialog for `items` whose plan is still being made.
    pub fn planning(items: Vec<PlanItem>, cfg: &Config) -> Self {
        RemovalModel {
            ids: items.iter().map(|i| i.id.clone()).collect(),
            items,
            plan: None,
            rows: Vec::new(),
            phase: Phase::Planning,
            permanent_mode: cfg.removal.mode == RemovalMode::Permanent,
            remind_trash: cfg.removal.remind_trash,
            run_only: None,
        }
    }

    /// A dialog showing `plan`: one row per step, notes from flags, warnings, the freed
    /// note; `ids` are the planned and skipped findings. Rows carry no component titles
    /// (see [`RemovalModel::from_plan_titled`]).
    pub fn from_plan(plan: Plan, cfg: &Config) -> Self {
        RemovalModel::from_plan_titled(plan, &FindingTitles::default(), cfg)
    }

    /// [`RemovalModel::from_plan`], with "<finding> → <component>" on every row whose step
    /// acts on a component, looked up in `titles`. `items` default to the plan's findings
    /// with their default components.
    pub fn from_plan_titled(plan: Plan, titles: &FindingTitles, cfg: &Config) -> Self {
        let mut ids: Vec<String> = Vec::new();
        let planned = plan.steps.iter().map(|s| &s.finding);
        for id in planned.chain(plan.skipped.iter().map(|(id, _)| id)) {
            if !ids.contains(&id.0) {
                ids.push(id.0.clone());
            }
        }
        let rows = plan.steps.iter().map(|s| row(s, titles)).collect();
        let items = ids
            .iter()
            .map(|id| PlanItem {
                id: id.clone(),
                components: None,
            })
            .collect();
        RemovalModel {
            plan: Some(plan),
            rows,
            phase: Phase::Ready,
            ..RemovalModel::planning(items, cfg)
        }
    }

    /// Apply a step event: `Started` marks the row running, `Finished` records its result.
    /// Events for indices outside the plan are ignored.
    pub fn apply(&mut self, ev: StepEvent) {
        match ev {
            StepEvent::Started { index } => {
                if let Some(r) = self.rows.iter_mut().find(|r| r.index == index) {
                    r.status = RowStatus::Running;
                    self.phase = Phase::Running {
                        current: Some(index),
                    };
                }
            }
            StepEvent::Finished(result) => {
                let index = result.index;
                self.record(result);
                if self.phase
                    == (Phase::Running {
                        current: Some(index),
                    })
                {
                    self.phase = Phase::Running { current: None };
                }
            }
        }
    }

    /// Record the executor's result: every row takes its final status from the report and
    /// the phase becomes [`Phase::Finished`]; a changed path gives [`Phase::Stale`] and an
    /// unknown plan [`Phase::Expired`] (both offer Re-plan), any other error [`Phase::Error`].
    pub fn finish(&mut self, r: Result<ExecutionReport, ExecuteError>) {
        self.phase = match r {
            Ok(report) => {
                for result in report.results {
                    self.record(result);
                }
                Phase::Finished(Summary {
                    freed: report.freed_total,
                    trashed: report.trashed_bytes,
                    stopped_at: report.stopped_at,
                    log: report.log_path,
                })
            }
            Err(ExecuteError::PlanStale { path }) => Phase::Stale { path },
            Err(ExecuteError::UnknownPlan(_)) => Phase::Expired,
            Err(e) => Phase::Error(e.to_string()),
        };
    }

    /// "3 steps · frees 1.1 GB", plus " · 2 items were skipped: <reason>" (distinct reasons
    /// joined by "; ") when the plan skipped findings. Empty while planning.
    pub fn header(&self) -> String {
        let Some(plan) = &self.plan else {
            return String::new();
        };
        let n = plan.steps.len();
        let mut s = format!(
            "{n} {} · frees {}",
            if n == 1 { "step" } else { "steps" },
            format::bytes(plan.total_freed)
        );
        if !plan.skipped.is_empty() {
            let mut reasons: Vec<&str> = Vec::new();
            for (_, reason) in &plan.skipped {
                if !reasons.contains(&reason.as_str()) {
                    reasons.push(reason);
                }
            }
            let k = plan.skipped.len();
            let items = if k == 1 { "item was" } else { "items were" };
            s.push_str(&format!(" · {k} {items} skipped: {}", reasons.join("; ")));
        }
        s
    }

    /// Run is available: the plan is shown and has steps.
    pub fn can_run(&self) -> bool {
        self.phase == Phase::Ready && !self.rows.is_empty()
    }

    /// The dialog may be closed (by its buttons only while nothing runs).
    pub fn closable(&self) -> bool {
        !matches!(self.phase, Phase::Running { .. })
    }

    /// The run starts with only the steps `only` (see [`run_only_steps`]); the rows of
    /// the others finish as skipped ([`OVERRIDE_SKIPPED_REASON`]).
    pub fn start_only(&mut self, only: Option<Vec<usize>>) {
        self.start();
        self.run_only = only;
    }

    /// The run starts: every row back to pending.
    pub fn start(&mut self) {
        for r in &mut self.rows {
            r.status = RowStatus::Pending;
            r.output.clear();
            r.reason = None;
        }
        self.phase = Phase::Running { current: None };
    }

    /// Plan the same ids again (after Stale or Expired): back to [`Phase::Planning`].
    pub fn replan(&mut self) {
        self.plan = None;
        self.rows.clear();
        self.phase = Phase::Planning;
    }

    /// The success toast after a run: "Freed X", or "Freed X, Y in the Trash". None for a
    /// run that stopped without freeing anything (its warning toast says enough).
    pub fn freed_message(&self) -> Option<String> {
        let Phase::Finished(s) = &self.phase else {
            return None;
        };
        if s.freed == 0 && s.stopped_at.is_some() {
            return None;
        }
        let mut msg = format!("Freed {}", format::bytes(s.freed));
        if s.trashed > 0 {
            msg.push_str(&format!(", {} in the Trash", format::bytes(s.trashed)));
        }
        Some(msg)
    }

    /// The warning toast after a run that stopped: "Stopped at step N: <reason>".
    pub fn stop_message(&self) -> Option<String> {
        let Phase::Finished(Summary {
            stopped_at: Some(i),
            ..
        }) = &self.phase
        else {
            return None;
        };
        let reason = self
            .rows
            .iter()
            .find(|r| r.index == *i)
            .and_then(|r| r.reason.clone())
            .unwrap_or_else(|| "the step failed".to_string());
        Some(format!("Stopped at step {}: {reason}", i + 1))
    }

    /// Store a finished step's result in its row.
    fn record(&mut self, result: StepResult) {
        let Some(r) = self.rows.iter_mut().find(|r| r.index == result.index) else {
            return;
        };
        let left_out = self
            .run_only
            .as_ref()
            .is_some_and(|o| !o.contains(&result.index));
        if result.status == StepStatus::NotRun && left_out {
            r.status = RowStatus::Skipped;
            r.output = result.output;
            r.reason = Some(OVERRIDE_SKIPPED_REASON.to_string());
            return;
        }
        r.status = match result.status {
            StepStatus::Done => RowStatus::Done,
            StepStatus::Failed => RowStatus::Failed,
            StepStatus::Skipped => RowStatus::Skipped,
            StepStatus::NotRun => RowStatus::NotRun,
        };
        if result.status == StepStatus::Done {
            r.freed = Some(result.freed);
        }
        r.output = result.output;
        r.reason = result.reason;
    }
}

/// The row for a planned step, with its notes: flags ("Needs an administrator password"
/// — not for a Quit step, which only asks the app —, [`GUI_ONLY_NOTE`], "Permanent", "Tool not installed:
/// <hint>"), then the freed note, then the remaining warnings.
fn row(step: &Step, titles: &FindingTitles) -> StepRow {
    let mut notes = Vec::new();
    let quit = matches!(step.kind, StepKind::Quit { .. });
    if step.flags.contains(StepFlags::INTERACTIVE) && !quit {
        notes.push("Needs an administrator password".to_string());
    }
    if step.flags.contains(StepFlags::GUI_ONLY) {
        notes.push(GUI_ONLY_NOTE.to_string());
    }
    if step.flags.contains(StepFlags::PERMANENT) {
        notes.push("Permanent".to_string());
    }
    let mut warnings = step.warnings.iter();
    if step.flags.contains(StepFlags::TOOL_MISSING) {
        notes.push(match warnings.next() {
            Some(w) => format!("Tool not installed: {w}"),
            None => "Tool not installed".to_string(),
        });
    }
    notes.extend(step.freed_note.clone());
    notes.extend(warnings.cloned());
    StepRow {
        index: step.index,
        component: step
            .component
            .and_then(|i| titles.component(&step.finding, i)),
        description: step.description.clone(),
        command: command_text_for(step),
        freed: step.freed,
        notes,
        status: RowStatus::Pending,
        output: String::new(),
        reason: None,
    }
}

/// The titles of the planned findings and of their components, so a step row can say
/// which part of which finding it removes.
#[derive(Clone, Debug, Default)]
pub struct FindingTitles(HashMap<String, (String, Vec<String>)>);

impl FindingTitles {
    /// The titles of `findings`.
    pub fn from_findings<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Self {
        FindingTitles(
            findings
                .into_iter()
                .map(|f| {
                    let comps = f.components.iter().map(|c| c.title.clone()).collect();
                    (f.id.0.clone(), (f.title.clone(), comps))
                })
                .collect(),
        )
    }

    /// "<finding title> → <component title>" for component `i` of `id`; only the finding
    /// title when `i` is unknown; `None` for an unknown finding.
    pub fn component(&self, id: &FindingId, i: usize) -> Option<String> {
        let (title, comps) = self.0.get(&id.0)?;
        Some(match comps.get(i) {
            Some(c) => format!("{title} → {c}"),
            None => title.clone(),
        })
    }
}

/// Whether "Empty Trash" is offered after a run: something went to the Trash, the
/// reminder is on, and Trash steps used the real Trash (with `DISCKY_TRASH_BIN` set the
/// items are elsewhere, and emptying the real Trash would touch the user's data).
pub fn show_empty_trash(trashed: u64, remind_trash: bool, trash_overridden: bool) -> bool {
    trashed > 0 && remind_trash && !trash_overridden
}

/// Whether the plan runs its `INTERACTIVE` steps (Finder, administrator prompts, Quit): not
/// with a `DISCKY_TRASH_BIN` override, which is for tests and development, where those
/// routes would still reach real data.
pub fn allow_interactive(trash_overridden: bool) -> bool {
    !trash_overridden
}

/// The steps a run executes: with a `DISCKY_TRASH_BIN` override only the Trash/Remove
/// steps (commands — `brew`, `defaults`, `launchctl`, `pkgutil`, scripts —, quits and
/// Ollama deletes would act on the real system), otherwise all (`None`).
pub fn run_only_steps(plan: &Plan, trash_overridden: bool) -> Option<Vec<usize>> {
    trash_overridden.then(|| {
        plan.steps
            .iter()
            .filter(|s| matches!(s.kind, StepKind::Trash { .. } | StepKind::Remove { .. }))
            .map(|s| s.index)
            .collect()
    })
}

/// Shown in the dialog when the trash binary is overridden.
pub const OVERRIDE_NOTE: &str =
    "Trash bin overridden (DISCKY_TRASH_BIN): command steps are skipped";

/// The note on a `GUI_ONLY` step (a vendor uninstaller script).
pub const GUI_ONLY_NOTE: &str =
    "Runs the vendor's uninstaller as you; it may ask for a password itself";

/// The reason on the row of a step the dev override left out.
pub const OVERRIDE_SKIPPED_REASON: &str = "skipped (dev override)";

/// Shown instead of "Empty Trash" when the trash binary is overridden.
pub const TRASH_OVERRIDDEN_NOTE: &str =
    "Trash bin overridden (DISCKY_TRASH_BIN); Empty Trash disabled";

/// Why a scan (⌘R, the menu, the Overview) is refused while a plan runs.
pub const SCAN_BLOCKED_MESSAGE: &str =
    "A removal is running; wait for it to finish before scanning";

/// Why a second removal dialog is refused while a plan runs.
pub const REMOVAL_BUSY_MESSAGE: &str = "A removal is already running";

/// Why closing the window or quitting is refused while a plan runs.
pub const BUSY_MESSAGE: &str = "A removal is running; wait for it to finish before closing";

/// App-wide "a removal is running" state: a count of running plans (quitting, closing the
/// window, scanning and a second removal are refused while it is non-zero, so a step is
/// never cut off part-way) and the step running right now, which a quit Discky cannot
/// refuse (Dock, logout) records as interrupted.
#[derive(Clone, Debug, Default)]
pub struct RunFlag(Arc<RunState>);

#[derive(Debug, Default)]
struct RunState {
    running: AtomicUsize,
    current: Mutex<Option<(PlanId, Step)>>,
}

impl RunFlag {
    /// A plan is executing.
    pub fn is_running(&self) -> bool {
        self.0.running.load(Ordering::SeqCst) > 0
    }

    /// Mark a run as started; it counts until the returned token is dropped.
    pub fn start(&self) -> RunToken {
        self.0.running.fetch_add(1, Ordering::SeqCst);
        RunToken(self.0.clone())
    }

    /// The step that started running (`Some`), or none since the last one finished.
    /// Called from the executing thread.
    pub fn set_current(&self, step: Option<(PlanId, Step)>) {
        *self.0.current.lock().unwrap_or_else(|e| e.into_inner()) = step;
    }

    /// The step to record as interrupted when the app quits now: the current step, while
    /// a run is in progress.
    pub fn interrupted(&self) -> Option<(PlanId, Step)> {
        if !self.is_running() {
            return None;
        }
        self.0
            .current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Held for the length of a run; dropping it takes the run off its [`RunFlag`].
#[derive(Debug)]
pub struct RunToken(Arc<RunState>);

impl Drop for RunToken {
    /// The last run ended: no step is running any more (also when the executor never
    /// reported its last step finished).
    fn drop(&mut self) {
        if self.0.running.fetch_sub(1, Ordering::SeqCst) == 1 {
            *self.0.current.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FindingTitles, Phase, RemovalModel, RowStatus, RunFlag, Summary, allow_interactive,
        show_empty_trash,
    };
    use discky_core::PlanItem;
    use discky_core::findings::FindingId;
    use discky_core::plan::execute::{
        ExecuteError, ExecutionReport, StepEvent, StepResult, StepStatus,
    };
    use discky_core::plan::{Plan, PlanId, Step, StepFlags, StepKind};
    use discky_core::{Config, RemovalMode};
    use std::path::PathBuf;

    fn step(index: usize, kind: StepKind, flags: StepFlags, freed: Option<u64>) -> Step {
        Step {
            index,
            finding: FindingId(format!("f{index}")),
            description: format!("Step {index}"),
            kind,
            freed,
            freed_note: None,
            flags,
            warnings: Vec::new(),
            fingerprints: Vec::new(),
            component: None,
        }
    }

    fn trash(index: usize, path: &str, flags: StepFlags, freed: u64) -> Step {
        step(
            index,
            StepKind::Trash {
                paths: vec![PathBuf::from(path)],
            },
            flags,
            Some(freed),
        )
    }

    fn plan(steps: Vec<Step>, skipped: &[(&str, &str)]) -> Plan {
        Plan {
            id: PlanId("p".into()),
            created_at: 0,
            total_freed: steps.iter().filter_map(|s| s.freed).sum(),
            steps,
            skipped: skipped
                .iter()
                .map(|(id, r)| (FindingId((*id).into()), (*r).into()))
                .collect(),
        }
    }

    fn result(index: usize, status: StepStatus, freed: u64) -> StepResult {
        StepResult {
            index,
            status,
            output: String::new(),
            freed,
            reason: None,
        }
    }

    #[test]
    fn rows_carry_flag_notes_and_commands() {
        let mut tool = step(
            1,
            StepKind::Command {
                argv: vec!["/opt/homebrew/bin/brew".into(), "cleanup".into()],
                cwd: None,
                env: Vec::new(),
            },
            StepFlags::TOOL_MISSING,
            None,
        );
        tool.warnings = vec!["brew not found. Install Homebrew".into(), "Slow".into()];
        tool.freed_note = Some("Frees what brew reports".into());
        let p = plan(
            vec![
                trash(
                    0,
                    "/Library/Logs/X",
                    StepFlags::INTERACTIVE | StepFlags::PERMANENT,
                    5,
                ),
                tool,
            ],
            &[],
        );
        let mut cfg = Config::default();
        cfg.removal.mode = RemovalMode::Permanent;
        cfg.removal.remind_trash = false;
        let m = RemovalModel::from_plan(p, &cfg);
        assert!(m.permanent_mode);
        assert!(!m.remind_trash);
        assert_eq!(m.phase, Phase::Ready);
        assert_eq!(m.ids, ["f0", "f1"]);
        assert_eq!(m.rows.len(), 2);
        let r0 = &m.rows[0];
        assert_eq!(r0.index, 0);
        assert_eq!(r0.description, "Step 0");
        assert_eq!(r0.command, "Finder → Trash: /Library/Logs/X");
        assert_eq!(r0.freed, Some(5));
        assert_eq!(r0.status, RowStatus::Pending);
        assert_eq!(r0.notes, ["Needs an administrator password", "Permanent"]);
        let r1 = &m.rows[1];
        assert_eq!(r1.command, "/opt/homebrew/bin/brew cleanup");
        assert_eq!(r1.freed, None);
        assert_eq!(
            r1.notes,
            [
                "Tool not installed: brew not found. Install Homebrew",
                "Frees what brew reports",
                "Slow",
            ]
        );
    }

    #[test]
    fn apply_marks_running_then_done() {
        let p = plan(
            vec![
                trash(0, "/tmp/a", StepFlags::empty(), 10),
                trash(1, "/tmp/b", StepFlags::empty(), 20),
            ],
            &[],
        );
        let mut m = RemovalModel::from_plan(p, &Config::default());
        assert!(m.can_run());
        m.phase = Phase::Running { current: None };
        assert!(!m.can_run());
        m.apply(StepEvent::Started { index: 0 });
        assert_eq!(m.rows[0].status, RowStatus::Running);
        assert_eq!(m.rows[1].status, RowStatus::Pending);
        assert_eq!(m.phase, Phase::Running { current: Some(0) });
        let mut done = result(0, StepStatus::Done, 7);
        done.output = "moved".into();
        m.apply(StepEvent::Finished(done));
        assert_eq!(m.rows[0].status, RowStatus::Done);
        assert_eq!(m.rows[0].freed, Some(7));
        assert_eq!(m.rows[0].output, "moved");
        m.apply(StepEvent::Started { index: 1 });
        let mut failed = result(1, StepStatus::Failed, 0);
        failed.reason = Some("exit 1".into());
        m.apply(StepEvent::Finished(failed));
        assert_eq!(m.rows[1].status, RowStatus::Failed);
        assert_eq!(m.rows[1].reason.as_deref(), Some("exit 1"));
        // An index outside the plan is ignored.
        m.apply(StepEvent::Started { index: 9 });
        assert_eq!(m.rows.len(), 2);
    }

    #[test]
    fn stale_error_maps_to_replan() {
        let p = plan(vec![trash(0, "/tmp/a", StepFlags::empty(), 1)], &[]);
        let mut m = RemovalModel::from_plan(p.clone(), &Config::default());
        m.phase = Phase::Running { current: None };
        m.finish(Err(ExecuteError::PlanStale {
            path: PathBuf::from("/tmp/a"),
        }));
        assert_eq!(
            m.phase,
            Phase::Stale {
                path: PathBuf::from("/tmp/a")
            }
        );
        assert!(!m.can_run());

        let mut m = RemovalModel::from_plan(p, &Config::default());
        m.finish(Err(ExecuteError::UnknownPlan("p".into())));
        assert_eq!(m.phase, Phase::Expired);
        assert!(!m.can_run());
        assert!(m.closable());
        m.replan();
        assert_eq!(m.phase, Phase::Planning);

        let items = ["a", "b"].map(|id| PlanItem {
            id: id.into(),
            components: None,
        });
        let m = RemovalModel::planning(items.to_vec(), &Config::default());
        assert_eq!(m.items, items);
        assert_eq!(m.phase, Phase::Planning);
        assert_eq!(m.ids, ["a", "b"]);
        assert!(m.rows.is_empty());
        assert!(!m.can_run());
    }

    #[test]
    fn header_counts_steps_and_skipped() {
        let one = plan(
            vec![trash(0, "/tmp/a", StepFlags::empty(), 1_100_000_000)],
            &[],
        );
        let m = RemovalModel::from_plan(one, &Config::default());
        assert_eq!(m.header(), "1 step · frees 1.1 GB");

        let three = plan(
            vec![
                trash(0, "/tmp/a", StepFlags::empty(), 600_000_000),
                trash(1, "/tmp/b", StepFlags::empty(), 400_000_000),
                trash(2, "/tmp/c", StepFlags::empty(), 100_000_000),
            ],
            &[("x", "Marked do-not-touch"), ("y", "Marked do-not-touch")],
        );
        let m = RemovalModel::from_plan(three, &Config::default());
        assert_eq!(m.ids, ["f0", "f1", "f2", "x", "y"]);
        assert_eq!(
            m.header(),
            "3 steps · frees 1.1 GB · 2 items were skipped: Marked do-not-touch"
        );

        let mixed = plan(
            Vec::new(),
            &[
                ("x", "Marked do-not-touch"),
                ("y", "Unknown finding id (rescan?)"),
            ],
        );
        let m = RemovalModel::from_plan(mixed, &Config::default());
        assert!(!m.can_run());
        assert_eq!(
            m.header(),
            "0 steps · frees 0 B · 2 items were skipped: Marked do-not-touch; \
             Unknown finding id (rescan?)"
        );

        let single = plan(Vec::new(), &[("x", "Nothing to remove")]);
        let m = RemovalModel::from_plan(single, &Config::default());
        assert_eq!(
            m.header(),
            "0 steps · frees 0 B · 1 item was skipped: Nothing to remove"
        );
    }

    #[test]
    fn finish_summary_uses_report_totals() {
        let p = plan(
            vec![
                trash(0, "/tmp/a", StepFlags::empty(), 10),
                trash(1, "/tmp/b", StepFlags::empty(), 20),
                trash(2, "/tmp/c", StepFlags::empty(), 30),
            ],
            &[],
        );
        let mut m = RemovalModel::from_plan(p, &Config::default());
        m.phase = Phase::Running { current: None };
        // Only the first step's events arrived; the report settles every row.
        m.apply(StepEvent::Started { index: 0 });
        let mut failed = result(1, StepStatus::Failed, 0);
        failed.reason = Some("Finder refused".into());
        failed.output = "error -1743".into();
        let report = ExecutionReport {
            plan: PlanId("p".into()),
            results: vec![
                result(0, StepStatus::Done, 9),
                failed,
                result(2, StepStatus::NotRun, 0),
            ],
            freed_total: 9,
            trashed_bytes: 9,
            stopped_at: Some(1),
            log_path: PathBuf::from("/tmp/home/removals.log"),
        };
        m.finish(Ok(report));
        assert_eq!(
            m.phase,
            Phase::Finished(Summary {
                freed: 9,
                trashed: 9,
                stopped_at: Some(1),
                log: PathBuf::from("/tmp/home/removals.log"),
            })
        );
        let statuses: Vec<_> = m.rows.iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [RowStatus::Done, RowStatus::Failed, RowStatus::NotRun]
        );
        assert_eq!(m.rows[0].freed, Some(9));
        assert_eq!(m.rows[1].output, "error -1743");
        assert_eq!(
            m.freed_message().as_deref(),
            Some("Freed 9 B, 9 B in the Trash")
        );
        assert_eq!(
            m.stop_message().as_deref(),
            Some("Stopped at step 2: Finder refused")
        );
    }

    #[test]
    fn empty_trash_hidden_when_trash_bin_overridden() {
        assert!(show_empty_trash(5, true, false));
        assert!(!show_empty_trash(5, true, true));
        assert!(!show_empty_trash(0, true, false));
        assert!(!show_empty_trash(5, false, false));
    }

    #[test]
    fn stopped_run_that_freed_nothing_has_no_success_toast() {
        let p = plan(vec![trash(0, "/tmp/a", StepFlags::empty(), 10)], &[]);
        let mut m = RemovalModel::from_plan(p, &Config::default());
        let mut failed = result(0, StepStatus::Failed, 0);
        failed.reason = Some("exit 1".into());
        m.finish(Ok(ExecutionReport {
            plan: PlanId("p".into()),
            results: vec![failed],
            freed_total: 0,
            trashed_bytes: 0,
            stopped_at: Some(0),
            log_path: PathBuf::from("/tmp/home/removals.log"),
        }));
        assert_eq!(m.freed_message(), None);
        assert_eq!(
            m.stop_message().as_deref(),
            Some("Stopped at step 1: exit 1")
        );

        // A run that finished but freed nothing (already absent) still says so.
        let p = plan(vec![trash(0, "/tmp/a", StepFlags::empty(), 10)], &[]);
        let mut m = RemovalModel::from_plan(p, &Config::default());
        m.finish(Ok(ExecutionReport {
            plan: PlanId("p".into()),
            results: vec![result(0, StepStatus::Done, 0)],
            freed_total: 0,
            trashed_bytes: 0,
            stopped_at: None,
            log_path: PathBuf::from("/tmp/home/removals.log"),
        }));
        assert_eq!(m.freed_message().as_deref(), Some("Freed 0 B"));
    }

    #[test]
    fn interactive_steps_are_skipped_when_the_trash_bin_is_overridden() {
        assert!(allow_interactive(false));
        assert!(!allow_interactive(true));
    }

    #[test]
    fn override_runs_only_trash_steps() {
        use super::{OVERRIDE_SKIPPED_REASON, run_only_steps};
        let quit = step(
            0,
            StepKind::Quit {
                bundle_id: "com.x".into(),
            },
            StepFlags::INTERACTIVE,
            None,
        );
        let brew = step(
            1,
            StepKind::Command {
                argv: vec!["brew".into(), "uninstall".into()],
                cwd: None,
                env: Vec::new(),
            },
            StepFlags::empty(),
            None,
        );
        let t = trash(2, "/tmp/a", StepFlags::empty(), 5);
        let remove = step(
            3,
            StepKind::Remove {
                paths: vec![PathBuf::from("/tmp/b")],
            },
            StepFlags::PERMANENT,
            Some(1),
        );
        let p = plan(vec![quit, brew, t, remove], &[]);
        assert_eq!(run_only_steps(&p, false), None);
        assert_eq!(run_only_steps(&p, true), Some(vec![2, 3]));

        // Rows of the steps left out say why.
        let mut m = RemovalModel::from_plan(p.clone(), &Config::default());
        m.start_only(run_only_steps(&p, true));
        m.finish(Ok(ExecutionReport {
            plan: PlanId("p".into()),
            results: vec![
                result(0, StepStatus::NotRun, 0),
                result(1, StepStatus::NotRun, 0),
                result(2, StepStatus::Done, 5),
                result(3, StepStatus::Done, 1),
            ],
            freed_total: 6,
            trashed_bytes: 5,
            stopped_at: None,
            log_path: PathBuf::from("/tmp/home/removals.log"),
        }));
        for i in [0, 1] {
            assert_eq!(m.rows[i].status, RowStatus::Skipped);
            assert_eq!(m.rows[i].reason.as_deref(), Some(OVERRIDE_SKIPPED_REASON));
        }
        assert_eq!(m.rows[2].reason, None);
        assert_eq!(OVERRIDE_SKIPPED_REASON, "skipped (dev override)");
    }

    #[test]
    fn run_flag_counts_tokens() {
        let flag = RunFlag::default();
        let a = flag.start();
        let b = flag.start();
        drop(a);
        assert!(flag.is_running());
        drop(b);
        assert!(!flag.is_running());
    }

    #[test]
    fn run_flag_reports_the_running_step_only_while_running() {
        let flag = RunFlag::default();
        let s = trash(1, "/tmp/a", StepFlags::empty(), 1);
        flag.set_current(Some((PlanId("p".into()), s.clone())));
        // Nothing runs: nothing to record as interrupted.
        assert!(flag.interrupted().is_none());
        let token = flag.start();
        let (plan, step) = flag.interrupted().unwrap();
        assert_eq!(plan, PlanId("p".into()));
        assert_eq!(step.index, 1);
        flag.set_current(None);
        assert!(flag.interrupted().is_none());
        flag.set_current(Some((PlanId("p".into()), s)));
        drop(token);
        assert!(flag.interrupted().is_none());
        // A stale step from an earlier run is not reported by the next one.
        let _next = flag.start();
        assert!(flag.interrupted().is_none());
    }

    #[test]
    fn run_flag_clears_when_token_drops() {
        let flag = RunFlag::default();
        assert!(!flag.is_running());
        let token = flag.start();
        let shared = flag.clone();
        assert!(shared.is_running());
        drop(token);
        assert!(!flag.is_running());
        assert!(!shared.is_running());
    }

    #[test]
    fn rows_show_component_titles() {
        use discky_core::findings::{Component, ComponentKind, ComponentRemoval, Finding, Removal};
        use discky_core::rules::{Category, SafetyLabel};
        let comp = |title: &str| Component {
            kind: ComponentKind::ApplicationSupport,
            title: title.into(),
            path: None,
            allocated: 0,
            freed_if_deleted: 0,
            modified: None,
            default_on: true,
            removal: ComponentRemoval::Trash,
            note: None,
            covered_by_cask: false,
        };
        let finding = Finding {
            id: FindingId("f0".into()),
            category: Category::Apps,
            title: "TeamViewer".into(),
            subtitle: None,
            path: None,
            node: None,
            allocated: 0,
            logical: 0,
            freed_if_deleted: 0,
            modified: None,
            label: SafetyLabel::AppData,
            rule_id: "apps".into(),
            explain: String::new(),
            removal: Removal::None,
            flags: Vec::new(),
            components: vec![comp("Application"), comp("Application Support")],
        };
        let titles = FindingTitles::from_findings([&finding]);
        let mut with = trash(0, "/tmp/a", StepFlags::empty(), 1);
        with.component = Some(1);
        with.warnings = vec!["Homebrew zap skipped: shared".into()];
        let without = trash(1, "/tmp/b", StepFlags::empty(), 1);
        let mut unknown = trash(2, "/tmp/c", StepFlags::empty(), 1);
        unknown.finding = FindingId("f0".into());
        unknown.component = Some(7);
        let m = RemovalModel::from_plan_titled(
            plan(vec![with, without, unknown], &[]),
            &titles,
            &Config::default(),
        );
        assert_eq!(
            m.rows[0].component.as_deref(),
            Some("TeamViewer → Application Support")
        );
        assert_eq!(m.rows[0].notes, ["Homebrew zap skipped: shared"]);
        assert_eq!(m.rows[1].component, None);
        // An index the titles do not know falls back to the finding title.
        assert_eq!(m.rows[2].component.as_deref(), Some("TeamViewer"));
        // Without titles, rows have no component line.
        let plain = RemovalModel::from_plan(
            plan(vec![trash(0, "/tmp/a", StepFlags::empty(), 1)], &[]),
            &Config::default(),
        );
        assert_eq!(plain.rows[0].component, None);
    }
}
