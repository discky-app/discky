//! A category screen (mockup B): toolbar, filter, findings table and the action bar.

pub mod selection;
pub mod table;

use std::time::{SystemTime, UNIX_EPOCH};

use discky_core::RemovalMode;
use discky_core::findings::Finding;
use discky_core::rules::Category;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{self, Input, InputEvent, InputState};
use gpui_kit::component::tab::{Tab, TabBar};
use gpui_kit::component::table::{DataTable, TableEvent, TableState};
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, IconName, Selectable as _, Sizable as _, StyledExt as _,
    h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{AppState, CATEGORY_TABLE_CONTEXT, FocusFilter, RemoveSelected, ToggleCheck};
use crate::format;
use discky_core::findings::apps::{RULE_APP, RULE_LEFTOVERS, RULE_RECEIPTS};
use discky_core::query::is_unused_app;
use table::{FindingsDelegate, Layout, ROW_HEIGHT, SortBy};

/// The filter tabs of the Applications screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppsTab {
    /// Apps not opened for `apps::UNUSED_DAYS` days, or never (unknown counts).
    Unused,
    /// Every installed app.
    All,
    /// Leftover groups of removed apps and the orphan package receipts.
    Leftovers,
}

/// The filter tabs, in the order the segmented control shows them.
const APPS_TABS: [AppsTab; 3] = [AppsTab::Unused, AppsTab::All, AppsTab::Leftovers];

impl AppsTab {
    /// "Not opened in 6 months (19)", "All (47)", "Leftovers (53)".
    fn label(self, count: usize) -> String {
        let name = match self {
            AppsTab::Unused => "Not opened in 6 months",
            AppsTab::All => "All",
            AppsTab::Leftovers => "Leftovers",
        };
        format!("{name} ({})", format::count(count as u64))
    }
}

/// The Applications findings `tab` shows, in the order of `findings`; `now` is Unix
/// seconds. Unused = installed apps not opened for `UNUSED_DAYS` days (an unknown last use
/// counts as not opened), All = installed apps, Leftovers = leftover groups and receipts.
pub fn apps_filter(findings: &[Finding], now: i64, tab: AppsTab) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| match tab {
            AppsTab::Unused => is_unused_app(f, now),
            AppsTab::All => f.rule_id == RULE_APP,
            AppsTab::Leftovers => f.rule_id == RULE_LEFTOVERS || f.rule_id == RULE_RECEIPTS,
        })
        .collect()
}

/// What a category screen asks of the app.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "emitted once per click; the brief's interface carries the finding by value"
)]
pub enum CategoryEvent {
    /// A row was selected: show this finding in the inspector.
    Inspect(Finding),
    /// "Remove…" (or backspace) with these checked finding ids.
    RemoveRequested(Vec<String>),
    /// No row is selected any more (the selected finding is gone after a reload, or the
    /// filter hides it): close the inspector.
    Cleared,
}

/// One category's findings: toolbar (title, count, sort, filter), the table and, while
/// something is checked, the action bar.
pub struct CategoryView {
    category: Category,
    layout: Layout,
    table: Entity<TableState<FindingsDelegate>>,
    filter: Entity<InputState>,
    sort: SortBy,
    /// The Applications filter tab (ignored by other categories).
    apps_tab: AppsTab,
    /// Every finding of the category as last loaded, and the time it was loaded (Unix
    /// seconds): the Applications tabs choose from these and count them.
    loaded: Vec<Finding>,
    now: i64,
    filter_visible: bool,
    focus: FocusHandle,
    /// Move keyboard focus to the table on the next render (the screen was just shown).
    focus_table: bool,
    /// The table's last measured width, which sizes the flexible columns.
    table_width: Pixels,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<CategoryEvent> for CategoryView {}

impl CategoryView {
    /// Build the screen for `category` from the engine's current snapshot.
    pub fn new(category: Category, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let home = discky_core::paths::home_dir().unwrap_or_default();
        let layout = Layout::for_category(category);
        let table = cx.new(|cx| {
            TableState::new(FindingsDelegate::new(layout, home), window, cx)
                .sortable(false)
                .col_movable(false)
                .col_resizable(false)
                .col_selectable(false)
        });
        let filter = cx.new(|cx| InputState::new(window, cx).placeholder("Filter by name or path"));
        let subscriptions = vec![
            cx.subscribe_in(&table, window, Self::on_table_event),
            cx.subscribe_in(&filter, window, Self::on_filter_event),
            // Checkbox clicks change the delegate; the action bar follows.
            cx.observe(&table, |_, _, cx| cx.notify()),
        ];
        let mut view = CategoryView {
            category,
            layout,
            table,
            filter,
            sort: SortBy::Size,
            apps_tab: AppsTab::Unused,
            loaded: Vec::new(),
            now: 0,
            filter_visible: false,
            focus: cx.focus_handle(),
            focus_table: true,
            table_width: px(0.),
            _subscriptions: subscriptions,
        };
        view.reload(cx);
        view
    }

    /// Re-query the category's findings (after a scan or refresh); checked findings that
    /// are gone are dropped, the rest stay checked.
    pub fn reload(&mut self, cx: &mut Context<Self>) {
        let (findings, _) = cx.global::<AppState>().engine.findings(
            Some(self.category),
            None,
            0,
            None,
            0,
            usize::MAX,
        );
        self.now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        self.loaded = findings;
        self.show_loaded(cx);
    }

    /// Hand the loaded findings to the table: on the Applications screen only those of the
    /// current tab (checked findings outside it are dropped).
    fn show_loaded(&mut self, cx: &mut Context<Self>) {
        let rows: Vec<Finding> = match self.layout {
            Layout::Apps => apps_filter(&self.loaded, self.now, self.apps_tab)
                .into_iter()
                .cloned()
                .collect(),
            _ => self.loaded.clone(),
        };
        let now = self.now;
        self.update_rows(cx, move |d| d.set_findings(rows, now));
    }

    fn set_apps_tab(&mut self, tab: AppsTab, cx: &mut Context<Self>) {
        if self.apps_tab != tab {
            self.apps_tab = tab;
            self.show_loaded(cx);
        }
    }

    /// Ask for keyboard focus on the table when the screen is next drawn.
    pub fn request_focus(&mut self, cx: &mut Context<Self>) {
        self.focus_table = true;
        cx.notify();
    }

    /// Change the rows with `change`, keeping the selected row on the same finding (or
    /// clearing it when that finding is no longer shown).
    fn update_rows(&mut self, cx: &mut Context<Self>, change: impl FnOnce(&mut FindingsDelegate)) {
        self.table.update(cx, |t, cx| {
            let selected = t
                .selected_row()
                .and_then(|ix| t.delegate().row(ix))
                .map(|f| f.id.clone());
            change(t.delegate_mut());
            t.refresh(cx);
            if let Some(id) = selected {
                match t.delegate().position(&id) {
                    Some(ix) => t.set_selected_row(ix, cx),
                    None => t.clear_selection(cx),
                }
            }
            cx.notify();
        });
    }

    fn set_sort(&mut self, by: SortBy, cx: &mut Context<Self>) {
        if self.sort != by {
            self.sort = by;
            self.update_rows(cx, |d| d.set_sort(by));
        }
    }

    /// Size the flexible columns to the table's measured width.
    fn set_table_width(&mut self, width: Pixels, cx: &mut Context<Self>) {
        if (width - self.table_width).abs() < px(0.5) {
            return;
        }
        self.table_width = width;
        self.table.update(cx, |t, cx| {
            if t.delegate_mut().set_table_width(f32::from(width)) {
                t.refresh(cx);
                cx.notify();
            }
        });
    }

    fn on_table_event(
        &mut self,
        table: &Entity<TableState<FindingsDelegate>>,
        event: &TableEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            TableEvent::SelectRow(ix) => {
                if let Some(f) = table.read(cx).delegate().row(*ix).cloned() {
                    cx.emit(CategoryEvent::Inspect(f));
                }
            }
            // Emitted by `clear_selection`, which `update_rows` calls when the selected
            // finding is no longer shown.
            TableEvent::ClearSelection => cx.emit(CategoryEvent::Cleared),
            _ => {}
        }
    }

    fn on_filter_event(
        &mut self,
        filter: &Entity<InputState>,
        event: &InputEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let InputEvent::Change = event {
            let needle = filter.read(cx).value().to_string();
            self.update_rows(cx, |d| d.set_needle(&needle));
        }
    }

    /// Show the filter field and put the cursor in it.
    fn show_filter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.filter_visible = true;
        self.filter.update(cx, |f, cx| f.focus(window, cx));
        cx.notify();
    }

    /// Clear and hide the filter field; focus goes back to the table.
    fn hide_filter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.filter.update(cx, |f, cx| f.set_value("", window, cx));
        self.update_rows(cx, |d| d.set_needle(""));
        self.filter_visible = false;
        window.focus(&self.table.focus_handle(cx), cx);
        cx.notify();
    }

    /// Whether the filter field has the keyboard (its own keys then win over ours).
    fn filter_focused(&self, window: &Window, cx: &App) -> bool {
        self.filter.focus_handle(cx).is_focused(window)
    }

    fn on_toggle_check(&mut self, _: &ToggleCheck, window: &mut Window, cx: &mut Context<Self>) {
        if self.filter_focused(window, cx) {
            // Let the space reach the text field.
            cx.propagate();
            return;
        }
        self.table.update(cx, |t, cx| {
            if let Some(ix) = t.selected_row()
                && t.delegate_mut().toggle_row(ix)
            {
                cx.notify();
            }
        });
    }

    fn on_remove_selected(
        &mut self,
        _: &RemoveSelected,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.filter_focused(window, cx) {
            cx.propagate();
            return;
        }
        self.request_removal(cx);
    }

    /// Emit [`CategoryEvent::RemoveRequested`] when something is checked.
    fn request_removal(&mut self, cx: &mut Context<Self>) {
        let ids = self.table.read(cx).delegate().checked_ids();
        if !ids.is_empty() {
            cx.emit(CategoryEvent::RemoveRequested(ids));
        }
    }

    /// Title and count, the sort control and the filter button.
    fn toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let delegate = self.table.read(cx).delegate();
        let total = delegate.all().len();
        let shown = delegate.shown_count();
        let count = if shown == total {
            format::count(total as u64)
        } else {
            format!(
                "{} of {}",
                format::count(shown as u64),
                format::count(total as u64)
            )
        };
        let sort_tabs = self.layout.sort_tabs();
        let selected = sort_tabs
            .iter()
            .position(|(by, _)| *by == self.sort)
            .unwrap_or(0);
        let apps_tabs = (self.layout == Layout::Apps).then(|| {
            let selected = APPS_TABS
                .iter()
                .position(|t| *t == self.apps_tab)
                .unwrap_or(0);
            TabBar::new("apps-filter")
                .segmented()
                .small()
                .selected_index(selected)
                .children(APPS_TABS.iter().map(|&tab| {
                    let count = apps_filter(&self.loaded, self.now, tab).len();
                    Tab::new().label(tab.label(count))
                }))
                .on_click(cx.listener(|this, ix: &usize, _, cx| {
                    if let Some(tab) = APPS_TABS.get(*ix) {
                        this.set_apps_tab(*tab, cx);
                    }
                }))
        });
        h_flex()
            .flex_shrink_0()
            .gap_3()
            .px_4()
            .py_3()
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_2()
                    .items_baseline()
                    .child(
                        div()
                            .text_lg()
                            .font_semibold()
                            .child(self.category.to_string()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(count),
                    ),
            )
            .children(apps_tabs)
            .child(
                TabBar::new("sort")
                    .segmented()
                    .small()
                    .selected_index(selected)
                    .children(sort_tabs.iter().map(|(_, label)| Tab::new().label(*label)))
                    .on_click(cx.listener(move |this, ix: &usize, _, cx| {
                        if let Some((by, _)) = sort_tabs.get(*ix) {
                            this.set_sort(*by, cx);
                        }
                    })),
            )
            .child(
                Button::new("show-filter")
                    .ghost()
                    .small()
                    .icon(IconName::Search)
                    .tooltip("Filter (⌘F)")
                    .selected(self.filter_visible)
                    .on_click(cx.listener(|this, _, window, cx| this.show_filter(window, cx))),
            )
    }

    /// "Selected N · X frees → Trash" with Show in Finder and Remove…, while something is
    /// checked.
    fn action_bar(&self, cx: &mut Context<Self>) -> Option<impl IntoElement + use<>> {
        let delegate = self.table.read(cx).delegate();
        let (summary, hidden) = (delegate.summary(), delegate.hidden_checked());
        if summary.count == 0 {
            return None;
        }
        let permanent =
            cx.global::<AppState>().engine.config().removal.mode == RemovalMode::Permanent;
        let theme = cx.theme();
        let (target, target_color) = if permanent {
            ("→ permanent deletion", theme.warning)
        } else {
            ("→ Trash", theme.muted_foreground)
        };
        let reveal = summary.first_path.clone();
        Some(
            h_flex()
                .flex_shrink_0()
                .gap_2()
                .px_4()
                .py_2()
                .border_t_1()
                .border_color(theme.border)
                .text_sm()
                .child(
                    h_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_1()
                        .child(selection_text(summary.count, summary.frees, hidden))
                        .child(div().text_color(target_color).child(target)),
                )
                .child(
                    Button::new("show-in-finder")
                        .small()
                        .label("Show in Finder")
                        .disabled(reveal.is_none())
                        .on_click(move |_, _, cx| {
                            if let Some(path) = &reveal {
                                cx.reveal_path(path);
                            }
                        }),
                )
                .child(
                    Button::new("remove")
                        .small()
                        .danger()
                        .label("Remove…")
                        .on_click(cx.listener(|this, _, _, cx| this.request_removal(cx))),
                ),
        )
    }
}

impl Render for CategoryView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if std::mem::take(&mut self.focus_table) && !self.filter_focused(window, cx) {
            window.focus(&self.table.focus_handle(cx), cx);
        }
        let empty = self.table.read(cx).delegate().all().is_empty();
        let muted = cx.theme().muted_foreground;
        let body = if empty {
            v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .text_color(muted)
                .child(format!("Nothing found in {}", self.category))
                .into_any_element()
        } else {
            let view = cx.weak_entity();
            div()
                .relative()
                .flex_1()
                .min_h_0()
                .mx_4()
                .mb_3()
                // Measures the table's width for the flexible Name and Where columns.
                .child(
                    canvas(
                        move |bounds, _, cx| {
                            let _ = view.update(cx, |v, cx| {
                                v.set_table_width(bounds.size.width, cx);
                            });
                        },
                        |_, _, _, _| {},
                    )
                    .absolute()
                    .size_full(),
                )
                .child(
                    DataTable::new(&self.table)
                        .with_size(px(ROW_HEIGHT))
                        .header_row_height(px(32.))
                        .stripe(false),
                )
                .into_any_element()
        };
        v_flex()
            .id("category")
            .key_context(CATEGORY_TABLE_CONTEXT)
            .track_focus(&self.focus)
            .size_full()
            .on_action(cx.listener(Self::on_toggle_check))
            .on_action(cx.listener(Self::on_remove_selected))
            .on_action(cx.listener(|this, _: &FocusFilter, window, cx| {
                this.show_filter(window, cx);
            }))
            .child(self.toolbar(cx))
            .when(self.filter_visible, |this| {
                this.child(
                    div()
                        .flex_shrink_0()
                        .px_4()
                        .pb_3()
                        // Escape in the field (which it does not handle itself) clears it.
                        .on_action(cx.listener(|this, _: &input::Escape, window, cx| {
                            this.hide_filter(window, cx);
                        }))
                        .child(Input::new(&self.filter).small().cleanable(true)),
                )
            })
            .child(body)
            .children(self.action_bar(cx))
    }
}

/// Findings for the unit tests of this module.
/// "Selected N · X frees", plus " · M hidden by filter" when the filter hides checked rows.
fn selection_text(count: usize, frees: u64, hidden: usize) -> String {
    let mut s = format!(
        "Selected {} · {} frees",
        format::count(count as u64),
        format::bytes(frees)
    );
    if hidden > 0 {
        s.push_str(&format!(
            " · {} hidden by filter",
            format::count(hidden as u64)
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{AppsTab, apps_filter, selection_text};
    use crate::category::fixtures::{app, finding};
    use discky_core::findings::AppSource;

    #[test]
    fn apps_filter_treats_unknown_as_unused() {
        let day = 86_400;
        let now = 1_000 * day;
        let mut leftovers = finding("l", "Readdle", 5);
        leftovers.rule_id = "app-leftovers".into();
        let mut receipts = finding("r", "Package receipts of removed apps", 0);
        receipts.rule_id = "pkg-receipts".into();
        let findings = vec![
            app("never", AppSource::Dragged, None, ""),
            app("old", AppSource::Dragged, Some(now - 180 * day), ""),
            app("recent", AppSource::Dragged, Some(now - 179 * day), ""),
            leftovers,
            receipts,
        ];
        let titles = |tab| -> Vec<String> {
            apps_filter(&findings, now, tab)
                .iter()
                .map(|f| f.title.clone())
                .collect()
        };
        assert_eq!(titles(AppsTab::Unused), ["never", "old"]);
        assert_eq!(titles(AppsTab::All), ["never", "old", "recent"]);
        assert_eq!(
            titles(AppsTab::Leftovers),
            ["Readdle", "Package receipts of removed apps"]
        );
    }

    #[test]
    fn selection_text_mentions_rows_hidden_by_the_filter() {
        assert_eq!(selection_text(3, 5_000_000, 0), "Selected 3 · 5 MB frees");
        assert_eq!(
            selection_text(3, 5_000_000, 2),
            "Selected 3 · 5 MB frees · 2 hidden by filter"
        );
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::path::PathBuf;

    use discky_core::findings::{AppSource, Finding, FindingId, Removal};
    use discky_core::rules::{Category, SafetyLabel};

    /// An app finding titled `title` installed from `source`, last opened at `modified`,
    /// with `subtitle` (empty for none) and bundle id `com.example.<title>`.
    pub fn app(title: &str, source: AppSource, modified: Option<i64>, subtitle: &str) -> Finding {
        let bundle = PathBuf::from(format!("/Applications/{title}.app"));
        Finding {
            id: FindingId::new("app", title),
            category: Category::Apps,
            title: title.to_string(),
            subtitle: (!subtitle.is_empty()).then(|| subtitle.to_string()),
            path: Some(bundle.clone()),
            node: None,
            allocated: 1,
            logical: 1,
            freed_if_deleted: 1,
            modified,
            label: SafetyLabel::AppData,
            rule_id: "apps".to_string(),
            explain: String::new(),
            removal: Removal::App {
                source,
                bundle,
                bundle_id: Some(format!("com.example.{title}")),
            },
            flags: Vec::new(),
            components: Vec::new(),
        }
    }

    /// A removable App caches finding `title` of `allocated` bytes (also its
    /// `freed_if_deleted`), at `/Users/me/Library/Caches/<key>`.
    pub fn finding(key: &str, title: &str, allocated: u64) -> Finding {
        let path = PathBuf::from(format!("/Users/me/Library/Caches/{key}"));
        Finding {
            id: FindingId::for_path(&path),
            category: Category::AppCaches,
            title: title.to_string(),
            subtitle: None,
            path: Some(path.clone()),
            node: None,
            allocated,
            logical: allocated,
            freed_if_deleted: allocated,
            modified: Some(0),
            label: SafetyLabel::Regenerates,
            rule_id: "test".to_string(),
            explain: String::new(),
            removal: Removal::Trash { paths: vec![path] },
            flags: Vec::new(),
            components: Vec::new(),
        }
    }
}
