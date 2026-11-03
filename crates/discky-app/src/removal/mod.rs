//! The removal dialog (mockup `02-uninstall.html`, variant 2): plans the requested
//! findings, shows every step and its exact command, runs the plan on a thread of its
//! own with live step statuses, and reports what was freed.

pub mod model;

use std::path::PathBuf;
use std::process::Command;

use discky_core::plan::execute::{ExecuteError, ExecutionReport, OSASCRIPT, StepEvent, StepSink};
use discky_core::{Config, ExecuteRequest, PlanItem};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, Sizable as _, StyledExt as _,
    WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::AppState;
use crate::format;
use model::{
    FindingTitles, INTERACTIVE_SKIPPED_NOTE, Phase, RemovalModel, RowStatus, RunToken, StepRow,
    TRASH_OVERRIDDEN_NOTE, allow_interactive, show_empty_trash,
};

/// Width of the dialog.
const DIALOG_WIDTH: f32 = 640.;
/// Height of the step list before it scrolls.
const ROWS_MAX_HEIGHT: f32 = 380.;
/// Lines of a failed step's output shown before that block scrolls.
const OUTPUT_LINES: f32 = 8.;

/// What the dialog tells the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemovalEvent {
    /// A run ended (finished, stale or failed): the snapshot may have changed.
    Ran,
}

/// The removal dialog's state; the dialog shell (`open`) renders it as its content.
pub struct RemovalDialog {
    model: RemovalModel,
    home: PathBuf,
    /// "Empty Trash" is running.
    emptying: bool,
    /// Trash steps run a `DISCKY_TRASH_BIN` override, not the system `trash`: no
    /// "Empty Trash", and interactive steps are skipped.
    trash_overridden: bool,
    /// Held while the plan executes; sets the app-wide [`model::RunFlag`].
    running: Option<RunToken>,
    /// The running plan request; replacing it drops a stale result.
    _plan: Task<()>,
    /// Feeds step events and the result of a run into `model`.
    _pump: Task<()>,
    _empty_trash: Task<()>,
}

impl EventEmitter<RemovalEvent> for RemovalDialog {}

/// Open the modal removal dialog for `items` (findings with their component selections)
/// and start planning them.
pub fn open(items: Vec<PlanItem>, window: &mut Window, cx: &mut App) -> Entity<RemovalDialog> {
    let view = cx.new(|cx| RemovalDialog::new(items, cx));
    let shown = view.clone();
    window.open_dialog(cx, move |dialog, _, cx| {
        let d = shown.read(cx);
        let closable = d.model.closable();
        dialog
            .title(d.title())
            .w(px(DIALOG_WIDTH))
            .close_button(closable)
            .overlay_closable(closable)
            .keyboard(closable)
            .child(shown.clone())
            .footer(d.footer(&shown, cx))
    });
    view
}

impl RemovalDialog {
    fn new(items: Vec<PlanItem>, cx: &mut Context<Self>) -> Self {
        let engine = cx.global::<AppState>().engine.clone();
        let cfg = engine.config();
        let trash_overridden =
            engine.trash_bin() != std::path::Path::new(discky_core::engine::TRASH_BIN);
        let mut dialog = RemovalDialog {
            model: RemovalModel::planning(items, &cfg),
            home: discky_core::paths::home_dir().unwrap_or_default(),
            emptying: false,
            trash_overridden,
            running: None,
            _plan: Task::ready(()),
            _pump: Task::ready(()),
            _empty_trash: Task::ready(()),
        };
        dialog.plan(cx);
        dialog
    }

    /// "Remove N items".
    fn title(&self) -> String {
        match self.model.items.len() {
            1 => "Remove 1 item".to_string(),
            n => format!("Remove {n} items"),
        }
    }

    /// Plan `model.items` afresh on the background executor (planning stats every path),
    /// with the titles of the planned findings and their components for the rows.
    fn plan(&mut self, cx: &mut Context<Self>) {
        let engine = cx.global::<AppState>().engine.clone();
        let items = self.model.items.clone();
        let work = cx.background_spawn(async move {
            // Titles come from the very snapshot the plan was made from.
            let (plan, titles) = match engine.plan_items_with_snapshot(&items) {
                Ok((plan, snap)) => {
                    let titles = FindingTitles::from_findings(
                        snap.findings
                            .iter()
                            .filter(|f| items.iter().any(|i| i.id == f.id.0)),
                    );
                    (Ok(plan), titles)
                }
                Err(e) => (Err(e.to_string()), FindingTitles::default()),
            };
            (plan, titles, engine.config())
        });
        self._plan = cx.spawn(async move |this, cx| {
            let (plan, titles, cfg) = work.await;
            let _ = this.update(cx, |this, cx| {
                this.planned(plan, &titles, &cfg);
                cx.notify();
            });
        });
    }

    /// Show the plan (keeping the requested items and ids), or the planning error.
    fn planned(
        &mut self,
        plan: Result<discky_core::plan::Plan, String>,
        titles: &FindingTitles,
        cfg: &Config,
    ) {
        match plan {
            Ok(plan) => {
                let items = std::mem::take(&mut self.model.items);
                let ids = std::mem::take(&mut self.model.ids);
                self.model = RemovalModel::from_plan_titled(plan, titles, cfg);
                self.model.items = items;
                self.model.ids = ids;
            }
            Err(e) => self.model.phase = Phase::Error(e),
        }
    }

    /// "Re-plan" after Stale or Expired: plan the same items again.
    fn replan(&mut self, cx: &mut Context<Self>) {
        self.model.replan();
        self.plan(cx);
        cx.notify();
    }

    /// Run the plan on a thread of its own; its step events and result come back through
    /// channels and are applied on the foreground.
    fn run(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.model.can_run() {
            return;
        }
        let Some(plan_id) = self.model.plan.as_ref().map(|p| p.id.clone()) else {
            return;
        };
        let state = cx.global::<AppState>();
        let engine = state.engine.clone();
        let flag = state.removal_running.clone();
        let steps = self
            .model
            .plan
            .as_ref()
            .map_or_else(Vec::new, |p| p.steps.clone());
        let (ev_tx, ev_rx) = smol::channel::unbounded::<StepEvent>();
        let (res_tx, res_rx) = smol::channel::bounded::<Result<ExecutionReport, ExecuteError>>(1);
        // Never panics: a closed channel (dialog gone) just drops the event. The running
        // step is kept in the app-wide flag, so a quit Discky cannot refuse logs it.
        let sink_plan = plan_id.clone();
        let sink_flag = flag.clone();
        let sink: StepSink = std::sync::Arc::new(move |ev| {
            match &ev {
                StepEvent::Started { index } => sink_flag.set_current(
                    steps
                        .iter()
                        .find(|s| s.index == *index)
                        .map(|s| (sink_plan.clone(), s.clone())),
                ),
                StepEvent::Finished(_) => sink_flag.set_current(None),
            }
            let _ = ev_tx.send_blocking(ev);
        });
        let req = ExecuteRequest {
            allow_interactive: allow_interactive(self.trash_overridden),
            only_steps: None,
            on_step: Some(sink),
        };
        // Counted before the thread starts, so a quit at any point sees the run.
        let token = flag.start();
        let spawned = std::thread::Builder::new()
            .name("discky-removal".into())
            .spawn(move || {
                let _ = res_tx.send_blocking(engine.execute_plan(&plan_id, req));
            });
        if let Err(e) = spawned {
            drop(token);
            self.model.phase = Phase::Error(format!("Cannot start the removal: {e}"));
            cx.notify();
            return;
        }
        self.model.start();
        self.running = Some(token);
        self._pump = cx.spawn_in(window, async move |this, cx| {
            // The event channel closes when the run ends and drops the sink.
            while let Ok(ev) = ev_rx.recv().await {
                let mut batch = vec![ev];
                while let Ok(ev) = ev_rx.try_recv() {
                    batch.push(ev);
                }
                let applied = this.update(cx, |this, cx| {
                    for ev in batch {
                        this.model.apply(ev);
                    }
                    cx.notify();
                });
                if applied.is_err() {
                    return;
                }
            }
            let result = res_rx.recv().await.unwrap_or_else(|_| {
                Err(ExecuteError::Io(std::io::Error::other(
                    "the removal stopped unexpectedly",
                )))
            });
            let _ = this.update_in(cx, |this, window, cx| this.ran(result, window, cx));
        });
        cx.notify();
    }

    /// The run ended: settle the rows, toast the result, tell the app to refresh.
    fn ran(
        &mut self,
        result: Result<ExecutionReport, ExecuteError>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.model.finish(result);
        self.running = None;
        if let Some(msg) = self.model.freed_message() {
            window.push_notification(Notification::success(msg), cx);
        }
        if let Some(msg) = self.model.stop_message() {
            window.push_notification(Notification::warning(msg), cx);
        }
        cx.emit(RemovalEvent::Ran);
        cx.notify();
    }

    /// "Empty Trash": confirm first, since Finder empties everything in the Trash.
    fn confirm_empty_trash(view: Entity<Self>, window: &mut Window, cx: &mut App) {
        window.open_dialog(cx, move |dialog, _, _| {
            let v = view.clone();
            dialog
                .title("Empty the Trash?")
                .w(px(420.))
                .child(
                    div()
                        .text_sm()
                        .whitespace_normal()
                        .child("This empties everything in the Trash, including items Discky did not put there."),
                )
                .footer(
                    h_flex()
                        .w_full()
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("empty-trash-cancel")
                                .label("Cancel")
                                .on_click(|_, window, cx| window.close_dialog(cx)),
                        )
                        .child(
                            Button::new("empty-trash-confirm")
                                .danger()
                                .label("Empty Trash")
                                .on_click(move |_, window, cx| {
                                    window.close_dialog(cx);
                                    v.update(cx, |d, cx| d.empty_trash(window, cx));
                                }),
                        ),
                )
        });
    }

    /// "Empty Trash": ask Finder to empty it, off the main thread, then toast the outcome.
    fn empty_trash(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.emptying {
            return;
        }
        self.emptying = true;
        let work = cx.background_spawn(async move {
            let out = Command::new(OSASCRIPT)
                .args(["-e", "tell application \"Finder\" to empty trash"])
                .output();
            match out {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => Err(tail(&String::from_utf8_lossy(&o.stderr))),
                Err(e) => Err(e.to_string()),
            }
        });
        self._empty_trash = cx.spawn_in(window, async move |this, cx| {
            let outcome = work.await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.emptying = false;
                let note = match outcome {
                    Ok(()) => Notification::info("Trash emptied"),
                    Err(e) => Notification::error(e),
                };
                window.push_notification(note, cx);
                cx.notify();
            });
        });
        cx.notify();
    }

    /// The footer for the current phase: a muted log note and the phase's buttons.
    fn footer(&self, view: &Entity<Self>, cx: &App) -> impl IntoElement + use<> {
        let muted = cx.theme().muted_foreground;
        let mut note = "Command output is written to the log";
        let close = || {
            Button::new("removal-close")
                .label("Close")
                .on_click(|_, window, cx| window.close_dialog(cx))
        };
        let buttons: Vec<AnyElement> = match &self.model.phase {
            Phase::Planning | Phase::Ready | Phase::Running { .. } => {
                let running = matches!(self.model.phase, Phase::Running { .. });
                let v = view.clone();
                vec![
                    Button::new("removal-cancel")
                        .label("Cancel")
                        .disabled(running)
                        .on_click(|_, window, cx| window.close_dialog(cx))
                        .into_any_element(),
                    Button::new("removal-run")
                        .danger()
                        .label("Run")
                        .disabled(!self.model.can_run())
                        .on_click(move |_, window, cx| {
                            v.update(cx, |d, cx| d.run(window, cx));
                        })
                        .into_any_element(),
                ]
            }
            Phase::Finished(summary) => {
                let log = summary.log.clone();
                let mut buttons = vec![
                    Button::new("removal-open-log")
                        .label("Open log")
                        .on_click(move |_, _, cx| cx.reveal_path(&log))
                        .into_any_element(),
                ];
                let offer = summary.trashed > 0 && self.model.remind_trash;
                if offer && self.trash_overridden {
                    note = TRASH_OVERRIDDEN_NOTE;
                }
                if show_empty_trash(
                    summary.trashed,
                    self.model.remind_trash,
                    self.trash_overridden,
                ) {
                    let v = view.clone();
                    buttons.push(
                        Button::new("removal-empty-trash")
                            .label("Empty Trash")
                            .disabled(self.emptying)
                            .on_click(move |_, window, cx| {
                                Self::confirm_empty_trash(v.clone(), window, cx);
                            })
                            .into_any_element(),
                    );
                }
                buttons.push(close().primary().into_any_element());
                buttons
            }
            Phase::Stale { .. } | Phase::Expired => {
                let v = view.clone();
                vec![
                    close().into_any_element(),
                    Button::new("removal-replan")
                        .primary()
                        .label("Re-plan")
                        .on_click(move |_, _, cx| v.update(cx, |d, cx| d.replan(cx)))
                        .into_any_element(),
                ]
            }
            Phase::Error(_) => vec![close().primary().into_any_element()],
        };
        h_flex()
            .w_full()
            .gap_2()
            .items_center()
            .child(div().flex_1().text_xs().text_color(muted).child(note))
            .children(buttons)
    }

    /// One step: status glyph, description, command, notes, freed; a failed step also
    /// shows its reason and output.
    fn step_row(&self, row: &StepRow, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, danger, mono) = (
            theme.muted_foreground,
            theme.danger,
            theme.mono_font_family.clone(),
        );
        let glyph = match row.status {
            RowStatus::Pending => div()
                .text_xs()
                .text_color(muted)
                .child((row.index + 1).to_string())
                .into_any_element(),
            RowStatus::Running => Spinner::new().small().into_any_element(),
            RowStatus::Done => Icon::new(IconName::Check)
                .small()
                .text_color(theme.success)
                .into_any_element(),
            RowStatus::Failed => Icon::new(IconName::Close)
                .small()
                .text_color(danger)
                .into_any_element(),
            RowStatus::Skipped | RowStatus::NotRun => {
                div().text_color(muted).child("–").into_any_element()
            }
        };
        let freed = row.freed.map_or_else(|| "—".to_string(), format::bytes);
        let failed = row.status == RowStatus::Failed;
        let output = (failed && !row.output.trim().is_empty()).then(|| {
            div()
                .id(("removal-output", row.index))
                .mt_1()
                .p_2()
                .max_h(rems(OUTPUT_LINES * 1.25))
                .rounded(theme.radius)
                .border_1()
                .border_color(theme.border)
                .bg(theme.muted)
                .font_family(mono.clone())
                .text_xs()
                .whitespace_normal()
                .overflow_y_scrollbar()
                .child(row.output.trim_end().to_string())
        });
        h_flex()
            .items_start()
            .gap_3()
            .py_2()
            .border_b_1()
            .border_color(theme.border)
            .child(
                h_flex()
                    .flex_shrink_0()
                    .w(px(20.))
                    .h(px(20.))
                    .justify_center()
                    .child(glyph),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .children(
                        row.component
                            .clone()
                            .map(|c| div().text_sm().font_semibold().child(c)),
                    )
                    .child(div().text_sm().child(row.description.clone()))
                    .child(
                        div()
                            .text_xs()
                            .font_family(mono)
                            .text_color(muted)
                            .whitespace_normal()
                            .child(row.command.clone()),
                    )
                    .children(
                        row.notes
                            .iter()
                            .map(|n| div().text_xs().text_color(muted).child(n.clone())),
                    )
                    .when_some(
                        row.reason.clone().filter(|_| row.status != RowStatus::Done),
                        |this, reason| this.child(div().text_xs().text_color(danger).child(reason)),
                    )
                    .children(output),
            )
            .child(div().flex_shrink_0().text_sm().text_right().child(freed))
    }
}

/// The last non-empty line of `s`, or a generic message.
fn tail(s: &str) -> String {
    s.lines().rev().find(|l| !l.trim().is_empty()).map_or_else(
        || "Finder could not empty the Trash".to_string(),
        str::to_string,
    )
}

impl Render for RemovalDialog {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let (muted, warning, danger) = (theme.muted_foreground, theme.warning, theme.danger);
        let status: Option<AnyElement> = match &self.model.phase {
            Phase::Stale { path } => Some(
                div()
                    .text_sm()
                    .text_color(warning)
                    .child(format!(
                        "Changed since it was planned: {}",
                        format::home_relative(path, &self.home)
                    ))
                    .into_any_element(),
            ),
            Phase::Expired => Some(
                div()
                    .text_sm()
                    .text_color(warning)
                    .child("This plan has expired; Re-plan to plan the items again")
                    .into_any_element(),
            ),
            Phase::Error(msg) => Some(
                div()
                    .text_sm()
                    .text_color(danger)
                    .whitespace_normal()
                    .child(msg.clone())
                    .into_any_element(),
            ),
            _ => None,
        };
        let body = if self.model.phase == Phase::Planning {
            div()
                .text_sm()
                .text_color(muted)
                .child("Preparing…")
                .into_any_element()
        } else {
            let rows: Vec<_> = self
                .model
                .rows
                .iter()
                .map(|r| self.step_row(r, cx))
                .collect();
            div()
                .id("removal-rows")
                .max_h(px(ROWS_MAX_HEIGHT))
                .overflow_y_scrollbar()
                .child(v_flex().children(rows))
                .into_any_element()
        };
        let theme = cx.theme();
        v_flex()
            .gap_3()
            .when(self.model.permanent_mode, |this| {
                this.child(
                    div()
                        .px_3()
                        .py_2()
                        .rounded(theme.radius)
                        .bg(theme.warning.opacity(0.12))
                        .text_sm()
                        .text_color(theme.warning)
                        .child("Files will be deleted permanently (Settings → Removal)"),
                )
            })
            .when(self.model.plan.is_some(), |this| {
                this.child(div().text_sm().text_color(muted).child(self.model.header()))
            })
            .when(self.trash_overridden, |this| {
                this.child(
                    div()
                        .text_xs()
                        .text_color(muted)
                        .child(INTERACTIVE_SKIPPED_NOTE),
                )
            })
            .child(body)
            .children(status)
    }
}
