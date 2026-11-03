//! The category table: pure sorting and filtering of findings, and the
//! [`FindingsDelegate`] that draws them in a kit `DataTable`.

use std::cmp::{Ordering, Reverse};
use std::path::PathBuf;

use discky_core::findings::{Finding, FindingId};
use discky_core::rules::SafetyLabel;
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::table::{Column, TableDelegate, TableState};
use gpui_kit::component::{ActiveTheme as _, Disableable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use super::selection::{Selection, SelectionSummary, is_checkable};
use crate::format;

/// Height of a body row.
pub const ROW_HEIGHT: f32 = 44.;
/// Width of the checkbox column.
const CHECK_WIDTH: f32 = 36.;
/// Width of the Modified column.
const MODIFIED_WIDTH: f32 = 110.;
/// Width of the Frees column.
const FREES_WIDTH: f32 = 120.;
/// Minimum width of the Name column.
const NAME_MIN: f32 = 240.;
/// Minimum width of the Where column.
const WHERE_MIN: f32 = 200.;
/// What the table draws besides its columns: the trailing spacer column (12 px), the
/// border and the vertical scrollbar.
const TABLE_CHROME: f32 = 26.;

/// Column indexes.
const COL_CHECK: usize = 0;
const COL_NAME: usize = 1;
const COL_WHERE: usize = 2;
const COL_MODIFIED: usize = 3;
const COL_FREES: usize = 4;

/// The order of the category table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortBy {
    /// Largest `allocated` first.
    Size,
    /// Oldest `modified` first; unknown dates last.
    Age,
    /// Title A–Z, case-insensitive; equal titles largest first.
    Name,
}

/// Sort `findings` in place by `by`.
pub fn sort(findings: &mut [Finding], by: SortBy) {
    match by {
        SortBy::Size => findings.sort_by_key(|f| Reverse(f.allocated)),
        SortBy::Age => findings.sort_by(|a, b| match (a.modified, b.modified) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => b.allocated.cmp(&a.allocated),
        }),
        SortBy::Name => {
            findings.sort_by_cached_key(|f| (f.title.to_lowercase(), Reverse(f.allocated)))
        }
    }
}

/// The findings whose title, subtitle or path contains `needle`, ignoring case; all of
/// them for an empty (or blank) needle. Keeps the order of `findings`.
pub fn filter<'a>(findings: &'a [Finding], needle: &str) -> Vec<&'a Finding> {
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return findings.iter().collect();
    }
    let hit = |s: &str| s.to_lowercase().contains(&needle);
    findings
        .iter()
        .filter(|f| {
            hit(&f.title)
                || f.subtitle.as_deref().is_some_and(hit)
                || f.path.as_deref().is_some_and(|p| hit(&p.to_string_lossy()))
        })
        .collect()
}

/// Widths of the flexible Name and Where columns for a table `table_width` wide: they
/// share what the fixed columns leave, 55 : 45, each at least its minimum.
pub fn flex_widths(table_width: f32) -> (f32, f32) {
    let free = table_width - CHECK_WIDTH - MODIFIED_WIDTH - FREES_WIDTH - TABLE_CHROME;
    let name = (free * 0.55).max(NAME_MIN);
    let place = (free - name).max(WHERE_MIN);
    (name, place)
}

/// Rows, checked findings and presentation inputs of the category table.
///
/// `all` holds every finding of the category in the current sort order; `rows` is the
/// filtered part the table shows. Sorting and filtering never touch `selection`.
pub struct FindingsDelegate {
    all: Vec<Finding>,
    rows: Vec<Finding>,
    selection: Selection,
    sort: SortBy,
    needle: String,
    /// `~` for the Where column.
    home: PathBuf,
    /// Unix seconds the Modified column is relative to (taken at each reload).
    now: i64,
    /// Name and Where column widths, see [`flex_widths`].
    widths: (f32, f32),
}

impl FindingsDelegate {
    /// An empty table sorted by size; `home` shortens paths to `~/…`.
    pub fn new(home: PathBuf) -> Self {
        FindingsDelegate {
            all: Vec::new(),
            rows: Vec::new(),
            selection: Selection::default(),
            sort: SortBy::Size,
            needle: String::new(),
            home,
            now: 0,
            widths: (NAME_MIN, WHERE_MIN),
        }
    }

    /// Replace the findings (after a scan or refresh) and drop checked ids that are gone.
    pub fn set_findings(&mut self, findings: Vec<Finding>, now: i64) {
        self.all = findings;
        self.now = now;
        self.selection.retain_present(&self.all);
        sort(&mut self.all, self.sort);
        self.apply_filter();
    }

    /// Re-order the rows.
    pub fn set_sort(&mut self, by: SortBy) {
        self.sort = by;
        sort(&mut self.all, by);
        self.apply_filter();
    }

    /// Show only rows matching `needle`, see [`filter`].
    pub fn set_needle(&mut self, needle: &str) {
        self.needle = needle.to_string();
        self.apply_filter();
    }

    /// Size the flexible columns for a table `table_width` wide. Returns whether the
    /// widths changed (the table then needs a `refresh`).
    pub fn set_table_width(&mut self, table_width: f32) -> bool {
        let widths = flex_widths(table_width);
        let changed = widths != self.widths;
        self.widths = widths;
        changed
    }

    fn apply_filter(&mut self) {
        self.rows = filter(&self.all, &self.needle)
            .into_iter()
            .cloned()
            .collect();
    }

    /// Every finding of the category, in table order (filter ignored).
    pub fn all(&self) -> &[Finding] {
        &self.all
    }

    /// The finding shown in row `ix`.
    pub fn row(&self, ix: usize) -> Option<&Finding> {
        self.rows.get(ix)
    }

    /// The row showing the finding `id`, if the filter lets it through.
    pub fn position(&self, id: &FindingId) -> Option<usize> {
        self.rows.iter().position(|f| &f.id == id)
    }

    /// How many rows the filter lets through.
    pub fn shown_count(&self) -> usize {
        self.rows.len()
    }

    /// Check or uncheck the finding in row `ix`; `false` when nothing changed.
    pub fn toggle_row(&mut self, ix: usize) -> bool {
        match self.rows.get(ix) {
            Some(f) => self.selection.toggle(f),
            None => false,
        }
    }

    /// Check or uncheck the finding `id`; `false` when nothing changed.
    fn toggle_id(&mut self, id: &FindingId) -> bool {
        match self.all.iter().find(|f| &f.id == id) {
            Some(f) => self.selection.toggle(f),
            None => false,
        }
    }

    /// Totals of all checked findings, including any the filter hides.
    pub fn summary(&self) -> SelectionSummary {
        self.selection.summary(&self.all)
    }

    /// How many checked findings the filter hides (they still count in [`Self::summary`]).
    pub fn hidden_checked(&self) -> usize {
        let shown = self.selection.summary(&self.rows).count;
        self.summary().count.saturating_sub(shown)
    }

    /// The checked ids, for `Engine::plan`.
    pub fn checked_ids(&self) -> Vec<String> {
        self.selection.ids()
    }
}

/// The badge of `label`: its text and theme colour.
pub(crate) fn badge(label: SafetyLabel, cx: &App) -> (&'static str, Hsla) {
    let theme = cx.theme();
    match label {
        SafetyLabel::Regenerates => ("regenerates", theme.success),
        SafetyLabel::AppData => ("app data", theme.muted_foreground),
        SafetyLabel::NeedsPassword => ("needs password", theme.warning),
        SafetyLabel::AppRunning => ("app running", theme.warning),
        SafetyLabel::DoNotTouch => ("do not touch", theme.danger),
    }
}

/// A small pill with `text` in `color`.
pub(crate) fn pill(text: impl Into<SharedString>, color: Hsla) -> Div {
    div()
        .flex_shrink_0()
        .px_1p5()
        .rounded_full()
        .border_1()
        .border_color(color.opacity(0.4))
        .bg(color.opacity(0.1))
        .text_color(color)
        .text_xs()
        .line_height(px(16.))
        .child(text.into())
}

impl TableDelegate for FindingsDelegate {
    fn columns_count(&self, _: &App) -> usize {
        5
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, place) = self.widths;
        match col_ix {
            COL_CHECK => Column::new("check", "")
                .width(px(CHECK_WIDTH))
                .resizable(false)
                .selectable(false),
            COL_NAME => Column::new("name", "Name")
                .min_width(px(NAME_MIN))
                .width(px(name)),
            COL_WHERE => Column::new("where", "Where")
                .min_width(px(WHERE_MIN))
                .width(px(place)),
            COL_MODIFIED => Column::new("modified", "Modified")
                .width(px(MODIFIED_WIDTH))
                .text_right(),
            _ => Column::new("frees", "Frees")
                .width(px(FREES_WIDTH))
                .text_right(),
        }
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(f) = self.rows.get(row_ix) else {
            return div().into_any_element();
        };
        let muted = cx.theme().muted_foreground;
        let cell = || h_flex().size_full().items_center().text_sm();
        match col_ix {
            COL_CHECK => {
                let id = f.id.clone();
                let table = cx.entity().downgrade();
                cell()
                    .justify_center()
                    .child(
                        Checkbox::new(("check", row_ix))
                            .checked(self.selection.contains(&f.id))
                            .disabled(!is_checkable(f))
                            .on_click(move |_, _, cx| {
                                let _ = table.update(cx, |t, cx| {
                                    if t.delegate_mut().toggle_id(&id) {
                                        cx.notify();
                                    }
                                });
                            }),
                    )
                    .into_any_element()
            }
            COL_NAME => {
                let (text, color) = badge(f.label, cx);
                // A path-less finding (a model) shows its subtitle under Where instead.
                let subtitle = f.subtitle.clone().filter(|_| f.path.is_some());
                cell()
                    .child(
                        v_flex()
                            .min_w_0()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .min_w_0()
                                    .child(div().min_w_0().truncate().child(f.title.clone()))
                                    .child(pill(text, color)),
                            )
                            .children(
                                subtitle
                                    .map(|s| div().text_xs().text_color(muted).truncate().child(s)),
                            ),
                    )
                    .into_any_element()
            }
            COL_WHERE => {
                let place = match &f.path {
                    Some(p) => format::home_relative(p, &self.home),
                    None => f.subtitle.clone().unwrap_or_default(),
                };
                cell()
                    .text_color(muted)
                    .font_family(cx.theme().mono_font_family.clone())
                    .text_xs()
                    .child(div().min_w_0().truncate().child(place))
                    .into_any_element()
            }
            COL_MODIFIED => cell()
                .justify_end()
                .text_color(muted)
                .child(match f.modified {
                    Some(t) => format::relative(t, self.now),
                    None => "—".to_string(),
                })
                .into_any_element(),
            COL_FREES => {
                let frees = format::bytes(f.freed_if_deleted);
                let allocated = format::bytes(f.allocated);
                cell()
                    .justify_end()
                    .child(
                        v_flex()
                            .items_end()
                            .child(frees.clone())
                            .when(allocated != frees, |this| {
                                this.child(div().text_xs().text_color(muted).child(allocated))
                            }),
                    )
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        h_flex()
            .size_full()
            .justify_center()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child("No matches")
    }

    fn cell_label(&self, row_ix: usize, col_ix: usize, _: &App) -> Option<SharedString> {
        let f = self.rows.get(row_ix)?;
        let text = match col_ix {
            COL_NAME => f.title.clone(),
            COL_WHERE => match &f.path {
                Some(p) => format::home_relative(p, &self.home),
                None => f.subtitle.clone().unwrap_or_default(),
            },
            COL_MODIFIED => f
                .modified
                .map_or_else(|| "—".to_string(), |t| format::relative(t, self.now)),
            COL_FREES => format::bytes(f.freed_if_deleted),
            _ => return None,
        };
        Some(text.into())
    }
}

#[cfg(test)]
mod tests {
    // Explicit imports, like the crate's other test modules (see `app.rs`).
    use super::{FindingsDelegate, SortBy, filter, flex_widths, sort};
    use crate::category::fixtures::finding;
    use std::path::PathBuf;

    #[test]
    fn hidden_checked_counts_checked_rows_the_filter_hides() {
        let mut d = FindingsDelegate::new(PathBuf::from("/Users/me"));
        d.set_findings(
            vec![
                finding("alpha", "Alpha", 3),
                finding("beta", "Beta", 2),
                finding("gamma", "Gamma", 1),
            ],
            0,
        );
        assert!(d.toggle_row(0));
        assert!(d.toggle_row(1));
        assert_eq!(d.hidden_checked(), 0);
        d.set_needle("alpha");
        assert_eq!(d.hidden_checked(), 1);
        d.set_needle("gamma");
        assert_eq!(d.hidden_checked(), 2);
        d.set_needle("");
        assert_eq!(d.hidden_checked(), 0);
    }

    fn titles(rows: &[discky_core::findings::Finding]) -> Vec<&str> {
        rows.iter().map(|f| f.title.as_str()).collect()
    }

    #[test]
    fn sort_age_puts_unknown_last() {
        let mut rows = vec![
            finding("a", "Unknown", 1),
            finding("b", "New", 2),
            finding("c", "Old", 3),
        ];
        rows[0].modified = None;
        rows[1].modified = Some(2_000);
        rows[2].modified = Some(1_000);
        sort(&mut rows, SortBy::Age);
        assert_eq!(titles(&rows), ["Old", "New", "Unknown"]);

        sort(&mut rows, SortBy::Size);
        assert_eq!(titles(&rows), ["Old", "New", "Unknown"]);

        rows.push(finding("d", "new", 50));
        sort(&mut rows, SortBy::Name);
        assert_eq!(titles(&rows), ["new", "New", "Old", "Unknown"]);
    }

    #[test]
    fn filter_matches_path_case_insensitively() {
        let mut rows = vec![
            finding("a", "Slack", 1),
            finding("b", "Zoom", 2),
            finding("c", "Model", 3),
        ];
        rows[0].path = Some(PathBuf::from(
            "/Users/me/Library/Caches/com.tinyspeck.Slack",
        ));
        rows[1].path = Some(PathBuf::from("/Users/me/Library/Caches/us.zoom.xos"));
        rows[2].path = None;
        rows[2].subtitle = Some("llama3:8b".to_string());

        let hits: Vec<&str> = filter(&rows, "TINYSPECK")
            .iter()
            .map(|f| f.title.as_str())
            .collect();
        assert_eq!(hits, ["Slack"]);
        assert_eq!(filter(&rows, "caches").len(), 2);
        assert_eq!(filter(&rows, "LLAMA").len(), 1);
        assert_eq!(filter(&rows, "zoom").len(), 1);
        assert_eq!(filter(&rows, "").len(), 3);
        assert_eq!(filter(&rows, "  ").len(), 3);
        assert!(filter(&rows, "nothing").is_empty());
    }

    #[test]
    fn flex_widths_fill_and_keep_minimums() {
        let (name, place) = flex_widths(1_000.);
        assert!((name + place - (1_000. - 36. - 110. - 120. - 26.)).abs() < 0.01);
        assert!(name > place);
        assert_eq!(flex_widths(300.), (240., 200.));
    }
}
