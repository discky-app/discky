//! The inspector (mockup `02-uninstall.html`, right column): everything known about the
//! selected finding and the exact commands its removal would run.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use discky_core::Inspection;
use discky_core::findings::{Finding, FindingId, Removal};
use discky_core::plan::{Plan, StepFlags, StepKind};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, IconName, Sizable as _, StyledExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{AppState, CloseInspector};
use crate::category::selection::is_checkable;
use crate::category::table::{badge, pill};
use crate::format;

/// Key context of the inspector; Escape closes it while it has focus.
pub const INSPECTOR_CONTEXT: &str = "Inspector";

/// Width of the label column of the metadata rows.
const LABEL_WIDTH: f32 = 84.;

/// What the inspector asks of the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InspectorEvent {
    /// "Remove…" for this finding id (the same path as the table's Remove…).
    RemoveRequested(String),
    /// The close button or Escape.
    Close,
}

/// The selected finding in full: metadata, largest children, and a preview of the
/// commands its removal would run.
pub struct Inspector {
    finding: Finding,
    /// `Engine::inspect` of the finding; `None` until the first load finishes.
    inspection: Option<Inspection>,
    /// The removal preview for `finding`; kept until the finding changes or a reload.
    plan: Option<Plan>,
    /// Why `Engine::plan` failed, shown instead of the commands.
    plan_error: Option<String>,
    /// An inspect/plan round is running in the background.
    loading: bool,
    home: PathBuf,
    focus: FocusHandle,
    /// The running load; replacing it cancels the previous one.
    _load: Task<()>,
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
        let mut inspector = Inspector {
            finding: f,
            inspection: None,
            plan: None,
            plan_error: None,
            loading: false,
            home: discky_core::paths::home_dir().unwrap_or_default(),
            focus: cx.focus_handle(),
            _load: Task::ready(()),
        };
        inspector.load(cx);
        inspector
    }

    /// The id of the finding shown.
    pub fn finding_id(&self) -> &FindingId {
        &self.finding.id
    }

    /// Show `f` instead. The same finding (fresh data after a reload or filter) only
    /// updates what is shown; another one is inspected and planned anew.
    pub fn set_finding(&mut self, f: Finding, cx: &mut Context<Self>) {
        let same = f.id == self.finding.id;
        self.finding = f;
        if !same {
            self.inspection = None;
            self.plan = None;
            self.plan_error = None;
            self.load(cx);
        }
        cx.notify();
    }

    /// Re-inspect and re-plan the finding after the snapshot changed.
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.load(cx);
    }

    /// Run `Engine::inspect` and (unless the finding is only shown) `Engine::plan` on the
    /// background executor; planning stats every path.
    fn load(&mut self, cx: &mut Context<Self>) {
        self.loading = true;
        let engine = cx.global::<AppState>().engine.clone();
        let id = self.finding.id.clone();
        let wants_plan = self.finding.removal != Removal::None;
        let target = id.0.clone();
        let work = cx.background_spawn(async move {
            let inspection = engine.inspect(&target);
            let plan = wants_plan.then(|| engine.plan(&[target]).map_err(|e| e.to_string()));
            (inspection, plan)
        });
        self._load = cx.spawn(async move |this, cx| {
            let (inspection, plan) = work.await;
            let _ = this.update(cx, |this, cx| {
                if this.finding.id != id {
                    return;
                }
                if let Some(f) = inspection.as_ref().and_then(|i| i.finding.clone())
                    && f.id == id
                {
                    this.finding = f;
                }
                this.inspection = inspection;
                (this.plan, this.plan_error) = match plan {
                    Some(Ok(p)) => (Some(p), None),
                    Some(Err(e)) => (None, Some(e)),
                    None => (None, None),
                };
                this.loading = false;
                cx.notify();
            });
        });
        cx.notify();
    }

    /// Title, subtitle and the close button.
    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let muted = cx.theme().muted_foreground;
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
                    .child(
                        div()
                            .text_base()
                            .font_semibold()
                            .child(self.finding.title.clone()),
                    )
                    .children(
                        self.finding
                            .subtitle
                            .clone()
                            .map(|s| div().text_sm().text_color(muted).child(s)),
                    ),
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
    fn meta(&self, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, mono) = (theme.muted_foreground, theme.mono_font_family.clone());
        let f = &self.finding;
        let row = |label: &'static str, value: AnyElement| {
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
        };
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
            rows.push(row(
                "Path",
                div()
                    .id("inspector-path")
                    .cursor_pointer()
                    .font_family(mono)
                    .text_xs()
                    .hover(|s| s.underline())
                    .tooltip(|window, cx| {
                        gpui_kit::component::tooltip::Tooltip::new("Show in Finder")
                            .build(window, cx)
                    })
                    .on_click(move |_, _, cx| cx.reveal_path(&path))
                    .child(shown)
                    .into_any_element(),
            ));
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

    /// "What will run": the plan's commands with their notes, or why there are none.
    fn commands(&self, cx: &App) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, warning) = (theme.muted_foreground, theme.warning);
        let body = if self.finding.removal == Removal::None {
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
        } else if let (Some(plan), false) = (&self.plan, self.loading) {
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

    /// The bottom bar: "Remove…", disabled for findings that cannot be removed.
    fn footer(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let id = self.finding.id.0.clone();
        h_flex()
            .flex_shrink_0()
            .justify_end()
            .px_4()
            .py_2()
            .border_t_1()
            .border_color(cx.theme().border)
            .child(
                Button::new("inspector-remove")
                    .small()
                    .danger()
                    .label("Remove…")
                    .disabled(!is_checkable(&self.finding))
                    .on_click(cx.listener(move |_, _, _, cx| {
                        cx.emit(InspectorEvent::RemoveRequested(id.clone()));
                    })),
            )
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
                            .child(self.meta(cx))
                            .children(self.contents(cx))
                            .child(self.commands(cx)),
                    ),
            )
            .child(self.footer(cx))
    }
}

/// One entry of the "What will run" block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandLine {
    /// The shell command; empty for a comment-only entry (a skipped finding).
    pub text: String,
    /// Shown muted above the command as `# …` lines: the step's flags ("needs
    /// administrator password", "permanent", "tool not installed: <hint>"), then its
    /// `freed_note` on a line of its own.
    pub comment: Option<String>,
}

/// One [`CommandLine`] per step of `plan`, then one "skipped: <reason>" comment per
/// skipped finding.
pub fn command_lines(plan: &Plan) -> Vec<CommandLine> {
    let home = discky_core::paths::home_dir();
    let steps = plan.steps.iter().map(|step| {
        let mut notes = Vec::new();
        if step.flags.contains(StepFlags::INTERACTIVE) {
            notes.push("needs administrator password".to_string());
        }
        if step.flags.contains(StepFlags::PERMANENT) {
            notes.push("permanent".to_string());
        }
        if step.flags.contains(StepFlags::TOOL_MISSING) {
            notes.push(match step.warnings.first() {
                Some(w) => format!("tool not installed: {w}"),
                None => "tool not installed".to_string(),
            });
        }
        let mut comment = (!notes.is_empty()).then(|| notes.join(" · "));
        if let Some(note) = &step.freed_note {
            comment = Some(match comment {
                Some(c) => format!("{c}\n{note}"),
                None => note.clone(),
            });
        }
        CommandLine {
            text: command_text_in(&step.kind, home.as_deref()),
            comment,
        }
    });
    let skipped = plan.skipped.iter().map(|(_, reason)| CommandLine {
        text: String::new(),
        comment: Some(format!("skipped: {reason}")),
    });
    steps.chain(skipped).collect()
}

/// The shell form of `kind`, with paths shown relative to the home directory.
pub fn command_text(kind: &StepKind) -> String {
    command_text_in(kind, discky_core::paths::home_dir().as_deref())
}

/// [`command_text`] with an explicit home directory (`None`: paths stay absolute).
fn command_text_in(kind: &StepKind, home: Option<&Path>) -> String {
    let paths = |program: &str, paths: &[PathBuf]| {
        std::iter::once(program.to_string())
            .chain(paths.iter().map(|p| quote_path(p, home)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    match kind {
        StepKind::Quit { bundle_id } => format!(
            "osascript -e {}",
            quote(&format!("tell application id \"{bundle_id}\" to quit"))
        ),
        StepKind::Trash { paths: p } => paths("trash", p),
        StepKind::Remove { paths: p } => paths("rm -rf", p),
        StepKind::Command { argv, cwd } => {
            let line = argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
            match cwd {
                Some(dir) => format!("cd {} && {line}", quote_path(dir, home)),
                None => line,
            }
        }
        StepKind::OllamaDelete { url, model } => {
            let body = serde_json::json!({ "model": model }).to_string();
            format!(
                "curl -X DELETE {}/api/delete -d {}",
                quote(url.trim_end_matches('/')),
                quote(&body)
            )
        }
    }
}

/// `arg` as one shell word: unchanged when it is safe bare, else in single quotes (an
/// embedded `'` becomes `'\''`). Quoted when empty or containing whitespace or `'"\$`.
fn quote(arg: &str) -> String {
    let unsafe_char = |c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | '$');
    if !arg.is_empty() && !arg.contains(unsafe_char) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// `p` relative to `home` ("~/Library/Caches/x"), quoted like [`quote`]; the `~/` stays
/// outside the quotes so the shell still expands it (`~/'Application Support/X'`).
fn quote_path(p: &Path, home: Option<&Path>) -> String {
    let shown = match home {
        Some(home) => format::home_relative(p, home),
        None => p.to_string_lossy().into_owned(),
    };
    match shown.strip_prefix("~/") {
        Some(rest) => format!("~/{}", quote(rest)),
        None => quote(&shown),
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandLine, command_lines, command_text_in};
    use discky_core::findings::FindingId;
    use discky_core::plan::{Plan, PlanId, Step, StepFlags, StepKind};
    use std::path::{Path, PathBuf};

    const HOME: &str = "/Users/me";

    fn text(kind: StepKind) -> String {
        command_text_in(&kind, Some(Path::new(HOME)))
    }

    fn step(kind: StepKind, flags: StepFlags, warnings: &[&str]) -> Step {
        Step {
            index: 0,
            finding: FindingId("f".into()),
            description: String::new(),
            kind,
            freed: Some(1),
            freed_note: None,
            flags,
            warnings: warnings.iter().map(|w| w.to_string()).collect(),
            fingerprints: Vec::new(),
        }
    }

    fn plan(steps: Vec<Step>, skipped: Vec<(&str, &str)>) -> Plan {
        Plan {
            id: PlanId("p".into()),
            created_at: 0,
            steps,
            total_freed: 0,
            skipped: skipped
                .into_iter()
                .map(|(id, r)| (FindingId(id.into()), r.into()))
                .collect(),
        }
    }

    fn command(argv: &[&str]) -> StepKind {
        StepKind::Command {
            argv: argv.iter().map(|a| a.to_string()).collect(),
            cwd: None,
        }
    }

    #[test]
    fn command_text_quotes_args_with_spaces() {
        assert_eq!(
            text(command(&[
                "/opt/homebrew/bin/brew",
                "cleanup",
                "--prune=all"
            ])),
            "/opt/homebrew/bin/brew cleanup --prune=all"
        );
        assert_eq!(
            text(command(&[
                "tool",
                "two words",
                "it's",
                "$HOME",
                "a\"b",
                "back\\slash"
            ])),
            r#"tool 'two words' 'it'\''s' '$HOME' 'a"b' 'back\slash'"#
        );
        assert_eq!(text(command(&["tool", ""])), "tool ''");
    }

    #[test]
    fn command_text_runs_commands_in_their_directory() {
        let kind = StepKind::Command {
            argv: vec!["cargo".into(), "clean".into()],
            cwd: Some(PathBuf::from("/Users/me/My Projects/app")),
        };
        assert_eq!(text(kind), "cd ~/'My Projects/app' && cargo clean");
    }

    #[test]
    fn command_text_forms() {
        assert_eq!(
            text(StepKind::Quit {
                bundle_id: "com.example.App".into()
            }),
            r#"osascript -e 'tell application id "com.example.App" to quit'"#
        );
        assert_eq!(
            text(StepKind::Trash {
                paths: vec![
                    PathBuf::from("/Users/me/Library/Caches/pnpm"),
                    PathBuf::from("/Users/me/Library/Application Support/X"),
                    PathBuf::from("/Library/Logs/Y Z"),
                ]
            }),
            "trash ~/Library/Caches/pnpm ~/'Library/Application Support/X' '/Library/Logs/Y Z'"
        );
        assert_eq!(
            text(StepKind::Remove {
                paths: vec![PathBuf::from("/Users/me/.cache/x")]
            }),
            "rm -rf ~/.cache/x"
        );
        assert_eq!(
            text(StepKind::OllamaDelete {
                url: "http://127.0.0.1:11434/".into(),
                model: "llama3:8b".into()
            }),
            r#"curl -X DELETE http://127.0.0.1:11434/api/delete -d '{"model":"llama3:8b"}'"#
        );
    }

    #[test]
    fn command_lines_annotate_flags() {
        let p = plan(
            vec![
                step(
                    StepKind::Remove {
                        paths: vec![PathBuf::from("/Library/Logs/X")],
                    },
                    StepFlags::INTERACTIVE | StepFlags::PERMANENT,
                    &[],
                ),
                step(
                    command(&["uv", "cache", "clean"]),
                    StepFlags::TOOL_MISSING,
                    &["uv not found. brew install uv", "second"],
                ),
                step(command(&["x"]), StepFlags::TOOL_MISSING, &[]),
                step(
                    StepKind::Trash {
                        paths: vec![PathBuf::from("/tmp/a")],
                    },
                    StepFlags::empty(),
                    &[],
                ),
            ],
            vec![],
        );
        let lines = command_lines(&p);
        assert_eq!(lines.len(), 4);
        let first = lines[0].comment.as_deref().unwrap();
        assert!(first.contains("needs administrator password"), "{first}");
        assert!(first.contains("permanent"), "{first}");
        assert_eq!(first, "needs administrator password · permanent");
        assert_eq!(lines[0].text, "rm -rf /Library/Logs/X");
        assert_eq!(
            lines[1].comment.as_deref(),
            Some("tool not installed: uv not found. brew install uv")
        );
        assert_eq!(lines[2].comment.as_deref(), Some("tool not installed"));
        assert_eq!(lines[3].comment, None);
    }

    #[test]
    fn command_lines_add_freed_note_and_skipped() {
        let mut s = step(
            command(&["docker", "system", "prune"]),
            StepFlags::empty(),
            &[],
        );
        s.freed_note = Some("Docker reports what it freed".into());
        let mut t = step(command(&["y"]), StepFlags::PERMANENT, &[]);
        t.freed_note = Some("note".into());
        let lines = command_lines(&plan(vec![s, t], vec![("abc", "Do not touch")]));
        assert_eq!(
            lines,
            vec![
                CommandLine {
                    text: "docker system prune".into(),
                    comment: Some("Docker reports what it freed".into()),
                },
                CommandLine {
                    text: "y".into(),
                    comment: Some("permanent\nnote".into()),
                },
                CommandLine {
                    text: String::new(),
                    comment: Some("skipped: Do not touch".into()),
                },
            ]
        );
    }
}
