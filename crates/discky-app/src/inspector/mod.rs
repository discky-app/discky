//! The inspector (mockup `02-uninstall.html`, right column): everything known about the
//! selected finding and the exact commands its removal would run, or about a disk-map
//! path without a finding of its own (`node`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use discky_core::findings::{Component, Finding, FindingId, Removal};
use discky_core::plan::Plan;
use discky_core::rules::Category;
use discky_core::{Inspection, PlanItem};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::notification::Notification;
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, IconName, Sizable as _, StyledExt as _, WindowExt as _,
    h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

mod commands;
mod node;
pub mod selection;

pub use commands::{CommandLine, command_lines, command_text_for};
pub use selection::ComponentSelection;

use crate::app::{AppState, CloseInspector};
use crate::category::selection::is_checkable;
use crate::category::table::{badge, pill};
use crate::format;
use selection::{
    component_note, kind_tag, remove_enabled, same_parts, selectable, selection_current,
};

/// Key context of the inspector; Escape closes it while it has focus.
pub const INSPECTOR_CONTEXT: &str = "Inspector";

/// Width of the label column of the metadata rows.
const LABEL_WIDTH: f32 = 84.;

/// The toast when "Remove…" finds the finding's components changed since they were shown.
const FINDING_CHANGED: &str = "Finding changed; review the selection";

/// Quiet time after a component toggle before the plan preview is recomputed, so rapid
/// toggles plan once.
const REPLAN_DEBOUNCE: Duration = Duration::from_millis(150);

/// What the inspector shows.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "one per inspector; the brief's interface carries the finding by value"
)]
pub enum Subject {
    Finding(Finding),
    /// A disk-map tile that is no finding's own.
    Path(PathBuf),
}

/// What the inspector asks of the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InspectorEvent {
    /// "Remove…": the finding with its selected components (or `components: None` for a
    /// finding without components), the same path as the table's Remove….
    RemoveItems(Vec<PlanItem>),
    /// "Move to Trash…" / "Delete permanently…" of a path subject.
    RemovePaths(Vec<PathBuf>),
    /// "Show in {category}": show this finding's row on its category screen.
    ShowInCategory(FindingId),
    /// The close button or Escape.
    Close,
}

/// The selected finding in full: metadata, largest children, and a preview of the
/// commands its removal would run; or a path's metadata, children and removal button.
pub struct Inspector {
    subject: Subject,
    /// The checked entries of the finding's components (empty for a path).
    selection: ComponentSelection,
    /// `Engine::inspect` of the finding (`node::inspect_path` of a path); `None` until the
    /// first load finishes.
    inspection: Option<Inspection>,
    /// The removal preview for `finding` and `selection`; kept (dimmed) while a newer one
    /// is computed.
    plan: Option<Plan>,
    /// Why `Engine::plan_items` failed, shown instead of the commands.
    plan_error: Option<String>,
    /// An inspect round is running in the background.
    loading: bool,
    /// A plan preview is being computed (or waits out the toggle debounce).
    planning: bool,
    home: PathBuf,
    /// Offer "Show in {category}" for a finding subject (opened from the disk map).
    from_map: bool,
    /// The planner's refusal of a path subject (`plan::path_refusal`), loaded with
    /// `inspection`.
    refusal: Option<String>,
    focus: FocusHandle,
    /// The running inspection; replacing it cancels the previous one.
    _load: Task<()>,
    /// The running plan preview; replacing it cancels the previous one (the debounce).
    _plan: Task<()>,
}

impl EventEmitter<InspectorEvent> for Inspector {}

impl Focusable for Inspector {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Inspector {
    /// Show `f`; its inspection and removal plan are computed off the main thread.
    pub fn new(f: Finding, cx: &mut Context<Self>) -> Self {
        let selection = ComponentSelection::from_components(&f.components);
        Self::with_subject(Subject::Finding(f), selection, cx)
    }

    /// Show the disk-map path `path`; its inspection is computed off the main thread.
    pub fn new_path(path: PathBuf, cx: &mut Context<Self>) -> Self {
        Self::with_subject(Subject::Path(path), ComponentSelection::default(), cx)
    }

    fn with_subject(
        subject: Subject,
        selection: ComponentSelection,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut inspector = Inspector {
            subject,
            selection,
            inspection: None,
            plan: None,
            plan_error: None,
            loading: false,
            planning: false,
            home: discky_core::paths::home_dir().unwrap_or_default(),
            from_map: false,
            refusal: None,
            focus: cx.focus_handle(),
            _load: Task::ready(()),
            _plan: Task::ready(()),
        };
        inspector.load(cx);
        inspector
    }

    /// What is shown.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// The finding shown; `None` for a path.
    fn finding(&self) -> Option<&Finding> {
        match &self.subject {
            Subject::Finding(f) => Some(f),
            Subject::Path(_) => None,
        }
    }

    /// The id of the finding shown; `None` for a path.
    pub fn finding_id(&self) -> Option<&FindingId> {
        self.finding().map(|f| &f.id)
    }

    /// Offer "Show in {category}" for a finding subject: true when the inspector shows a
    /// disk-map tile (a category screen already shows the finding's row).
    pub fn set_from_map(&mut self, on: bool, cx: &mut Context<Self>) {
        if self.from_map != on {
            self.from_map = on;
            cx.notify();
        }
    }

    /// Show `f` instead. The same finding (fresh data after a reload or filter) only
    /// updates what is shown; another one is inspected and planned anew.
    pub fn set_finding(&mut self, f: Finding, cx: &mut Context<Self>) {
        if self.finding_id() == Some(&f.id) {
            if self.adopt(f) {
                self.replan(Duration::ZERO, cx);
            }
        } else {
            self.selection = ComponentSelection::from_components(&f.components);
            self.show(Subject::Finding(f), cx);
        }
        cx.notify();
    }

    /// Show the disk-map path `path` instead; nothing happens when it is already shown.
    pub fn set_path(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if matches!(&self.subject, Subject::Path(p) if *p == path) {
            return;
        }
        self.selection = ComponentSelection::default();
        self.show(Subject::Path(path), cx);
        cx.notify();
    }

    /// Switch to another subject and inspect it anew.
    fn show(&mut self, subject: Subject, cx: &mut Context<Self>) {
        self.subject = subject;
        self.inspection = None;
        self.refusal = None;
        self.plan = None;
        self.plan_error = None;
        self.load(cx);
    }

    /// Take fresh data for the same finding. The selection is kept while the components
    /// are the same parts (sizes may differ) and reset to the defaults otherwise; true when
    /// it was reset.
    fn adopt(&mut self, f: Finding) -> bool {
        let same = same_parts(&f.components, parts_of(&self.subject));
        self.subject = Subject::Finding(f);
        let parts = parts_of(&self.subject);
        if same {
            self.selection.retain_valid(parts);
        } else {
            self.selection = ComponentSelection::from_components(parts);
        }
        !same
    }

    /// What "Remove…" and the preview plan: the finding with exactly the checked
    /// components, or its defaults when it has none; `None` for a path.
    fn plan_request(&self) -> Option<PlanItem> {
        let f = self.finding()?;
        Some(if f.components.is_empty() {
            PlanItem::defaults(&f.id)
        } else {
            self.selection.items(&f.id.0, &f.components)
        })
    }

    /// Whether some component can be checked (a mise version's projects cannot).
    fn has_selectable(&self) -> bool {
        parts_of(&self.subject).iter().any(selectable)
    }

    /// The fresh finding is still being loaded while components are shown: their indices
    /// may not match the current snapshot yet.
    fn refreshing(&self) -> bool {
        self.loading && !parts_of(&self.subject).is_empty()
    }

    /// "Remove…": hand the selection to the removal dialog, unless the snapshot's finding
    /// no longer has the components on screen (then warn and reload them).
    fn request_removal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(f) = self.finding() else {
            return;
        };
        let snap = cx.global::<AppState>().engine.snapshot();
        let current = snap.as_ref().and_then(|s| {
            s.findings
                .iter()
                .find(|c| c.id == f.id)
                .map(|c| c.components.as_slice())
        });
        if !f.components.is_empty() && !selection_current(&f.components, current) {
            window.push_notification(Notification::warning(FINDING_CHANGED), cx);
            self.refresh(cx);
            return;
        }
        if let Some(item) = self.plan_request() {
            cx.emit(InspectorEvent::RemoveItems(vec![item]));
        }
    }

    /// Check or uncheck component `i` and recompute the preview after the debounce.
    fn set_component(&mut self, i: usize, on: bool, cx: &mut Context<Self>) {
        if self.selection.set(i, on, parts_of(&self.subject)) {
            self.replan(REPLAN_DEBOUNCE, cx);
        }
    }

    /// Re-inspect and re-plan the finding after the snapshot changed.
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.load(cx);
    }

    /// Run `Engine::inspect` on the background executor and recompute the plan preview.
    /// A finding with components is planned only once the fresh finding is adopted, so the
    /// checked indices never meet a newer component list than the one on screen.
    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let engine = cx.global::<AppState>().engine.clone();
        let id = match &self.subject {
            Subject::Finding(f) => f.id.clone(),
            Subject::Path(path) => {
                let path = path.clone();
                let target = path.clone();
                let home = self.home.clone();
                let work =
                    cx.background_spawn(async move { node::inspect_path(&engine, &target, &home) });
                self._load = cx.spawn(async move |this, cx| {
                    let inspection = work.await;
                    let _ = this.update(cx, |this, cx| {
                        if matches!(&this.subject, Subject::Path(p) if *p == path) {
                            (this.inspection, this.refusal) = match inspection {
                                Some((i, refusal)) => (Some(i), refusal),
                                None => (None, None),
                            };
                            this.loading = false;
                            cx.notify();
                        }
                    });
                });
                self.replan(Duration::ZERO, cx);
                cx.notify();
                return;
            }
        };
        let deferred = !parts_of(&self.subject).is_empty();
        let target = id.0.clone();
        let work = cx.background_spawn(async move { engine.inspect(&target) });
        self._load = cx.spawn(async move |this, cx| {
            let inspection = work.await;
            let _ = this.update(cx, |this, cx| {
                if this.finding_id() != Some(&id) {
                    return;
                }
                let reset = match inspection.as_ref().and_then(|i| i.finding.clone()) {
                    Some(f) if f.id == id => this.adopt(f),
                    _ => false,
                };
                this.inspection = inspection;
                this.loading = false;
                if deferred || reset {
                    this.replan(Duration::ZERO, cx);
                }
                cx.notify();
            });
        });
        if !deferred {
            self.replan(Duration::ZERO, cx);
        }
        cx.notify();
    }

    /// Recompute the plan preview for the current selection after `delay`, through
    /// `Engine::plan_items` on the background executor (planning stats every path). A newer
    /// call cancels this one; a result for a selection that changed meanwhile is dropped.
    /// Findings that are only shown get no plan.
    fn replan(&mut self, delay: Duration, cx: &mut Context<Self>) {
        let item = match self.plan_request() {
            Some(item) if self.finding().is_some_and(|f| f.removal != Removal::None) => item,
            _ => {
                self.plan = None;
                self.plan_error = None;
                self.planning = false;
                self._plan = Task::ready(());
                return;
            }
        };
        self.planning = true;
        let engine = cx.global::<AppState>().engine.clone();
        self._plan = cx.spawn(async move |this, cx| {
            if !delay.is_zero() {
                cx.background_executor().timer(delay).await;
            }
            let request = item.clone();
            let plan = cx
                .background_spawn(async move {
                    engine.plan_items(&[request]).map_err(|e| e.to_string())
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.plan_request().as_ref() != Some(&item) {
                    return;
                }
                (this.plan, this.plan_error) = match plan {
                    Ok(p) => (Some(p), None),
                    Err(e) => (None, Some(e)),
                };
                this.planning = false;
                cx.notify();
            });
        });
        cx.notify();
    }

    /// Title, subtitle and the close button.
    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let muted = cx.theme().muted_foreground;
        let (title, subtitle) = match &self.subject {
            Subject::Finding(f) => (f.title.clone(), f.subtitle.clone()),
            Subject::Path(p) => (node::title(p), None),
        };
        h_flex()
            .flex_shrink_0()
            .items_start()
            .gap_2()
            .px_4()
            .pt_4()
            .pb_2()
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .child(div().text_base().font_semibold().child(title))
                    .children(subtitle.map(|s| div().text_sm().text_color(muted).child(s))),
            )
            .child(
                Button::new("close-inspector")
                    .ghost()
                    .xsmall()
                    .icon(IconName::Close)
                    .tooltip("Close (Esc)")
                    .on_click(cx.listener(|_, _, _, cx| cx.emit(InspectorEvent::Close))),
            )
    }

    /// The metadata rows: category, rule, label, path, sizes, dates, flags, owner app.
    fn meta(&self, f: &Finding, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, mono) = (theme.muted_foreground, theme.mono_font_family.clone());
        let row = |label: &'static str, value: AnyElement| meta_row(label, value, muted);
        let mut rows = vec![row("Category", f.category.to_string().into_any_element())];
        if let Some((title, explain)) = self.inspection.as_ref().and_then(|i| i.rule.clone()) {
            rows.push(row(
                "Rule",
                v_flex()
                    .child(title)
                    .when(!explain.is_empty(), |this| {
                        this.child(div().text_xs().text_color(muted).child(explain))
                    })
                    .into_any_element(),
            ));
        }
        let (text, color) = badge(f.label, cx);
        rows.push(row(
            "Label",
            h_flex().child(pill(text, color)).into_any_element(),
        ));
        if let Some(path) = f.path.clone() {
            let shown = format::home_relative(&path, &self.home);
            rows.push(row("Path", path_link(path, shown, mono).into_any_element()));
        }
        let allocated = format::bytes(f.allocated);
        let logical = format::bytes(f.logical);
        rows.push(row(
            "Size",
            h_flex()
                .gap_1()
                .child(allocated.clone())
                .when(logical != allocated, |this| {
                    this.child(
                        div()
                            .text_color(muted)
                            .child(format!("· logical {logical}")),
                    )
                })
                .into_any_element(),
        ));
        rows.push(row(
            "Frees",
            format::bytes(f.freed_if_deleted).into_any_element(),
        ));
        if let Some(t) = f.modified.filter(|t| *t > 0) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            rows.push(row(
                "Modified",
                h_flex()
                    .gap_1()
                    .child(format::when(t))
                    .child(
                        div()
                            .text_color(muted)
                            .child(format!("· {}", format::relative(t, now))),
                    )
                    .into_any_element(),
            ));
        }
        if !f.flags.is_empty() {
            rows.push(row(
                "Flags",
                h_flex()
                    .flex_wrap()
                    .gap_1()
                    .children(f.flags.iter().map(|flag| pill(flag.clone(), muted)))
                    .into_any_element(),
            ));
        }
        if let Some(app) = self.inspection.as_ref().and_then(|i| i.owner_app.clone()) {
            rows.push(row("App", app.into_any_element()));
        }
        v_flex().gap_2().children(rows)
    }

    /// "Contents · top N": the largest children, when the finding is a directory.
    fn contents(&self, cx: &App) -> Option<impl IntoElement + use<>> {
        let children = &self.inspection.as_ref()?.children;
        if children.is_empty() {
            return None;
        }
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let rows = children.iter().map(|c| {
            let modified = if c.modified > 0 {
                format::relative(c.modified, now)
            } else {
                "—".to_string()
            };
            h_flex()
                .gap_2()
                .py_1()
                .border_b_1()
                .border_color(border)
                .text_sm()
                .child(div().flex_1().min_w_0().truncate().child(c.name.clone()))
                .child(
                    div()
                        .flex_shrink_0()
                        .text_xs()
                        .text_color(muted)
                        .child(modified),
                )
                .child(
                    div()
                        .flex_shrink_0()
                        .w(px(64.))
                        .text_right()
                        .child(format::bytes(c.allocated)),
                )
        });
        Some(
            v_flex()
                .child(section_label(
                    format!("Contents · top {}", children.len()),
                    muted,
                ))
                .children(rows),
        )
    }

    /// "Components · N": one row per component with its checkbox (disabled for parts that
    /// are only shown), title, kind, path, size and note. Replaces "Contents".
    fn components(&self, f: &Finding, cx: &mut Context<Self>) -> Option<impl IntoElement + use<>> {
        if f.components.is_empty() {
            return None;
        }
        let theme = cx.theme();
        let (muted, border, mono) = (
            theme.muted_foreground,
            theme.border,
            theme.mono_font_family.clone(),
        );
        let rows: Vec<_> = f
            .components
            .iter()
            .enumerate()
            .map(|(i, c)| self.component_row(i, c, muted, border, mono.clone(), cx))
            .collect();
        Some(
            v_flex()
                .child(section_label(
                    format!("Components · {}", f.components.len()),
                    muted,
                ))
                .children(rows),
        )
    }

    /// One component row (see [`Inspector::components`]).
    fn component_row(
        &self,
        i: usize,
        c: &Component,
        muted: Hsla,
        border: Hsla,
        mono: SharedString,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let path = c
            .path
            .as_ref()
            .map(|p| format::home_relative(p, &self.home));
        h_flex()
            .items_start()
            .gap_2()
            .py_1p5()
            .border_b_1()
            .border_color(border)
            .child(
                div().pt_0p5().child(
                    Checkbox::new(("component", i))
                        .checked(self.selection.is_on(i))
                        .disabled(!selectable(c))
                        .on_click(cx.listener(move |this, on: &bool, _, cx| {
                            this.set_component(i, *on, cx);
                            cx.notify();
                        })),
                ),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .child(
                        h_flex()
                            .gap_2()
                            .text_sm()
                            .child(div().min_w_0().truncate().child(c.title.clone()))
                            .children(kind_tag(c).map(|tag| {
                                div().flex_shrink_0().text_xs().text_color(muted).child(tag)
                            })),
                    )
                    .children(path.map(|p| {
                        div()
                            .font_family(mono)
                            .text_xs()
                            .text_color(muted)
                            .truncate()
                            .child(p)
                    }))
                    .children(
                        component_note(c).map(|n| div().text_xs().text_color(muted).child(n)),
                    ),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .w(px(64.))
                    .text_sm()
                    .text_right()
                    .child(format::bytes(c.allocated)),
            )
    }

    /// "What will run": the plan's commands with their notes, or why there are none.
    fn commands(&self, f: &Finding, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, warning) = (theme.muted_foreground, theme.warning);
        let body = if f.removal == Removal::None {
            div()
                .text_sm()
                .text_color(muted)
                .child("Nothing — this item is only shown")
                .into_any_element()
        } else if let Some(err) = &self.plan_error {
            div()
                .text_sm()
                .text_color(warning)
                .child(err.clone())
                .into_any_element()
        } else if let Some(plan) = &self.plan {
            let lines = command_lines(plan).into_iter().flat_map(|line| {
                let comments = line
                    .comment
                    .iter()
                    .flat_map(|c| c.lines().map(str::to_string).collect::<Vec<_>>())
                    .map(|c| div().text_color(muted).child(format!("# {c}")))
                    .collect::<Vec<_>>();
                let text = (!line.text.is_empty()).then(|| div().child(line.text));
                comments.into_iter().chain(text)
            });
            v_flex()
                .gap_0p5()
                .p_2()
                .rounded(theme.radius)
                .border_1()
                .border_color(theme.border)
                .bg(theme.muted)
                .font_family(theme.mono_font_family.clone())
                .text_xs()
                .when(self.planning, |this| this.opacity(0.6))
                .children(lines)
                .into_any_element()
        } else {
            div()
                .text_sm()
                .text_color(muted)
                .child("Preparing…")
                .into_any_element()
        };
        v_flex()
            .child(section_label("What will run".to_string(), muted))
            .child(body)
    }

    /// The bottom bar: "N components selected · frees X" when components can be checked,
    /// then "Remove…", disabled for findings that cannot be removed and when every
    /// checkable component is unchecked.
    fn footer(&self, f: &Finding, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);
        let selectable = self.has_selectable();
        let (count, bytes) = self.selection.summary(&f.components);
        let summary = selectable.then(|| {
            let noun = if count == 1 {
                "component"
            } else {
                "components"
            };
            div().text_xs().text_color(muted).child(format!(
                "{count} {noun} selected · frees {}",
                format::bytes(bytes)
            ))
        });
        let refreshing = self.refreshing();
        let disabled = !remove_enabled(is_checkable(f), selectable, count, refreshing);
        let show_in = self
            .from_map
            .then(|| show_in_button(f.category, f.id.clone(), cx));
        v_flex()
            .flex_shrink_0()
            .gap_1()
            .px_4()
            .py_2()
            .border_t_1()
            .border_color(border)
            .children(summary)
            .child(
                h_flex()
                    .justify_end()
                    .items_center()
                    .gap_2()
                    .when(refreshing, |this| {
                        this.child(div().text_xs().text_color(muted).child("Refreshing…"))
                    })
                    .children(show_in)
                    .child(
                        Button::new("inspector-remove")
                            .small()
                            .danger()
                            .label("Remove…")
                            .disabled(disabled)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.request_removal(window, cx);
                            })),
                    ),
            )
    }
}

/// One metadata row: the muted label column, then `value`.
fn meta_row(label: &'static str, value: AnyElement, muted: Hsla) -> Div {
    h_flex()
        .items_start()
        .gap_2()
        .text_sm()
        .child(
            div()
                .flex_shrink_0()
                .w(px(LABEL_WIDTH))
                .text_color(muted)
                .child(label),
        )
        .child(div().flex_1().min_w_0().child(value))
}

/// The "Path" value: `shown` in the mono font; a click reveals `path` in Finder.
fn path_link(path: PathBuf, shown: String, mono: SharedString) -> impl IntoElement {
    div()
        .id("inspector-path")
        .cursor_pointer()
        .font_family(mono)
        .text_xs()
        .hover(|s| s.underline())
        .tooltip(|window, cx| {
            gpui_kit::component::tooltip::Tooltip::new("Show in Finder").build(window, cx)
        })
        .on_click(move |_, _, cx| cx.reveal_path(&path))
        .child(shown)
}

/// "Show in {category}": asks the app to show finding `id` on its category screen.
fn show_in_button(category: Category, id: FindingId, cx: &mut Context<Inspector>) -> Button {
    Button::new("inspector-show-in")
        .small()
        .label(format!("Show in {category}"))
        .on_click(cx.listener(move |_, _, _, cx| {
            cx.emit(InspectorEvent::ShowInCategory(id.clone()));
        }))
}

/// The components of a finding subject; none for a path.
fn parts_of(subject: &Subject) -> &[Component] {
    match subject {
        Subject::Finding(f) => &f.components,
        Subject::Path(_) => &[],
    }
}

/// A small uppercase section heading ("CONTENTS · TOP 20").
fn section_label(text: String, muted: Hsla) -> Div {
    div()
        .mt_4()
        .mb_1p5()
        .text_xs()
        .text_color(muted)
        .child(text.to_uppercase())
}

impl Render for Inspector {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let warning = cx.theme().warning;
        let missing = self.inspection.as_ref().is_some_and(|i| !i.in_snapshot);
        let (body, footer) = match &self.subject {
            Subject::Finding(f) => {
                let body = v_flex()
                    .child(self.meta(f, cx))
                    .children(self.components(f, cx))
                    .when(f.components.is_empty(), |this| {
                        this.children(self.contents(cx))
                    })
                    .child(self.commands(f, cx));
                (
                    body.into_any_element(),
                    self.footer(f, cx).into_any_element(),
                )
            }
            Subject::Path(p) => {
                let mode = Self::removal_mode(cx);
                let rows = self.path_rows(mode);
                (
                    self.path_body(p, rows.as_ref(), cx).into_any_element(),
                    self.path_footer(p, rows.as_ref(), mode, cx)
                        .into_any_element(),
                )
            }
        };
        v_flex()
            .id("inspector")
            .key_context(INSPECTOR_CONTEXT)
            .track_focus(&self.focus)
            .size_full()
            .on_action(cx.listener(|_, _: &CloseInspector, _, cx| {
                cx.emit(InspectorEvent::Close);
            }))
            .child(self.header(cx))
            .child(
                div()
                    .id("inspector-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(
                        v_flex()
                            .px_4()
                            .pb_4()
                            .when(missing, |this| {
                                this.child(
                                    div().mb_2().text_sm().text_color(warning).child(
                                        "Not in the current snapshot (removed since the scan?)",
                                    ),
                                )
                            })
                            .child(body),
                    ),
            )
            .child(footer)
    }
}
