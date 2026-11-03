//! The category table: pure sorting and filtering of findings, and the
//! [`FindingsDelegate`] that draws them in a kit `DataTable`.

use std::cmp::{Ordering, Reverse};
use std::path::PathBuf;

use discky_core::findings::apps::{RULE_APP, RULE_LEFTOVERS, RULE_RECEIPTS};
use discky_core::findings::{AppSource, ComponentKind, Finding, FindingId, Removal};
use discky_core::rules::{Category, SafetyLabel};
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::table::{Column, TableDelegate, TableState};
use gpui_kit::component::{ActiveTheme as _, Disableable as _, h_flex, v_flex};
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
/// Width of the Applications table's Source column.
const SOURCE_WIDTH: f32 = 130.;
/// Width of the Applications table's Last opened column.
const LAST_OPENED_WIDTH: f32 = 120.;
/// Width of the Applications table's Total column (wide enough for its
/// "app 133 MB + leftovers 250 KB" line).
const TOTAL_WIDTH: f32 = 180.;
/// Width of the Language versions table's Status column.
const STATUS_WIDTH: f32 = 180.;
/// Width of the Language versions table's Size column.
const SIZE_WIDTH: f32 = 120.;
/// Minimum width of the Language versions table's Name column.
const VERSION_NAME_MIN: f32 = 200.;
/// What the table draws besides its columns: the trailing spacer column (12 px), the
/// border and the vertical scrollbar.
const TABLE_CHROME: f32 = 26.;

/// Column indexes. Every layout has five columns: check, name, then three that depend on
/// the [`Layout`] (Default: Where, Modified, Frees; Apps: Source, Last opened, Total;
/// Versions: Status, Where, Size).
const COL_CHECK: usize = 0;
const COL_NAME: usize = 1;
const COL_THIRD: usize = 2;
const COL_FOURTH: usize = 3;
const COL_FIFTH: usize = 4;

/// Which columns the category table shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// Name · Where · Modified · Frees (caches, models, builds, large & old).
    Default,
    /// Name (+ bundle id) · Source · Last opened · Total (Applications).
    Apps,
    /// Name · Status · Where · Size (Language versions).
    Versions,
}

impl Layout {
    /// The layout of `category`'s table.
    pub fn for_category(category: Category) -> Layout {
        match category {
            Category::Apps => Layout::Apps,
            Category::LanguageVersions => Layout::Versions,
            _ => Layout::Default,
        }
    }

    /// The sort tabs of this layout, in the order the segmented control shows them.
    pub fn sort_tabs(self) -> &'static [(SortBy, &'static str)] {
        match self {
            Layout::Default => &[
                (SortBy::Size, "Size"),
                (SortBy::Age, "Age"),
                (SortBy::Name, "Name"),
            ],
            Layout::Apps => &[
                (SortBy::Size, "Size"),
                (SortBy::LastOpened, "Last opened"),
                (SortBy::Name, "Name"),
            ],
            Layout::Versions => &[(SortBy::Size, "Size"), (SortBy::Name, "Tool")],
        }
    }
}

/// The order of the category table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortBy {
    /// Largest `allocated` first.
    Size,
    /// Oldest `modified` first; unknown dates last.
    Age,
    /// Title A–Z, case-insensitive; equal titles largest first.
    Name,
    /// Longest unused first: oldest `modified` first, unknown dates first of all (equal
    /// dates largest first).
    LastOpened,
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
        // `None < Some(_)`, so unknown last use comes first.
        SortBy::LastOpened => findings.sort_by_key(|f| (f.modified, Reverse(f.allocated))),
    }
}

/// Where an app came from ("cask · raycast", "pkg", "App Store", "drag & drop"); for a
/// leftover group "leftovers", for the orphan receipts "receipts"; empty otherwise.
pub fn source_text(f: &Finding) -> String {
    match &f.removal {
        Removal::App { source, .. } => match source {
            AppSource::Cask { token, .. } => format!("cask · {token}"),
            AppSource::Pkg { .. } => "pkg".to_string(),
            AppSource::AppStore => "App Store".to_string(),
            AppSource::Dragged => "drag & drop".to_string(),
        },
        _ if f.rule_id == RULE_LEFTOVERS => "leftovers".to_string(),
        _ if f.rule_id == RULE_RECEIPTS => "receipts".to_string(),
        _ => String::new(),
    }
}

/// Whether the finding's last-used date is an estimate (core marks its subtitle with `*`).
pub fn is_estimate(f: &Finding) -> bool {
    f.subtitle.as_deref().is_some_and(|s| s.contains('*'))
}

/// The Last opened cell: `relative` time, with `*` for an estimate; "never*" for an app
/// with no known use; "—" for a finding that is not an app and has no date.
pub fn last_opened_text(f: &Finding, now: i64) -> String {
    match f.modified {
        Some(t) => {
            let mut text = format::relative(t, now);
            if is_estimate(f) {
                text.push('*');
            }
            text
        }
        None if f.rule_id == RULE_APP => "never*".to_string(),
        None => "—".to_string(),
    }
}

/// The Status cell of a language version: its subtitle up to " · " ("global",
/// "pinned in 3 projects", "not referenced").
pub fn status_text(f: &Finding) -> String {
    let subtitle = f.subtitle.as_deref().unwrap_or_default();
    subtitle
        .split_once(" · ")
        .map_or(subtitle, |(status, _)| status)
        .to_string()
}

/// "app X + leftovers Y" under an app's total: X is the bundle component's `allocated`, Y
/// the rest of the finding's. `None` without a bundle component or without leftover bytes
/// (the total is then the bundle alone).
pub fn total_breakdown(f: &Finding) -> Option<String> {
    let bundle = f
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::AppBundle)?
        .allocated;
    let leftovers = f.allocated.saturating_sub(bundle);
    (leftovers > 0).then(|| {
        format!(
            "app {} + leftovers {}",
            format::bytes(bundle),
            format::bytes(leftovers)
        )
    })
}

/// The muted line under an app's name: its bundle id, or (a leftover group) the subtitle.
fn app_detail(f: &Finding) -> Option<String> {
    match &f.removal {
        Removal::App { bundle_id, .. } => bundle_id.clone(),
        _ => f.subtitle.clone(),
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

/// Widths of the flexible columns of a `layout` table `table_width` wide, each at least
/// its minimum. Default: Name and Where share what the fixed columns leave, 55 : 45. Apps:
/// Name takes all of it (the second width is unused). Versions: Name and Where, 50 : 50.
pub fn flex_widths(layout: Layout, table_width: f32) -> (f32, f32) {
    match layout {
        Layout::Default => {
            let free = table_width - CHECK_WIDTH - MODIFIED_WIDTH - FREES_WIDTH - TABLE_CHROME;
            let name = (free * 0.55).max(NAME_MIN);
            (name, (free - name).max(WHERE_MIN))
        }
        Layout::Apps => {
            let free = table_width
                - CHECK_WIDTH
                - SOURCE_WIDTH
                - LAST_OPENED_WIDTH
                - TOTAL_WIDTH
                - TABLE_CHROME;
            (free.max(NAME_MIN), 0.)
        }
        Layout::Versions => {
            let free = table_width - CHECK_WIDTH - STATUS_WIDTH - SIZE_WIDTH - TABLE_CHROME;
            let name = (free * 0.5).max(VERSION_NAME_MIN);
            (name, (free - name).max(WHERE_MIN))
        }
    }
}

/// Rows, checked findings and presentation inputs of the category table.
///
/// `all` holds every finding of the category in the current sort order; `rows` is the
/// filtered part the table shows. Sorting and filtering never touch `selection`.
pub struct FindingsDelegate {
    layout: Layout,
    all: Vec<Finding>,
    rows: Vec<Finding>,
    selection: Selection,
    sort: SortBy,
    needle: String,
    /// `~` for the Where column.
    home: PathBuf,
    /// Unix seconds the Modified column is relative to (taken at each reload).
    now: i64,
    /// Widths of the flexible columns, see [`flex_widths`].
    widths: (f32, f32),
}

impl FindingsDelegate {
    /// An empty `layout` table sorted by size; `home` shortens paths to `~/…`.
    pub fn new(layout: Layout, home: PathBuf) -> Self {
        FindingsDelegate {
            layout,
            all: Vec::new(),
            rows: Vec::new(),
            selection: Selection::default(),
            sort: SortBy::Size,
            needle: String::new(),
            home,
            now: 0,
            widths: flex_widths(layout, 0.),
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
        let widths = flex_widths(self.layout, table_width);
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

impl FindingsDelegate {
    /// The Where text of `f`: its path under `~`, or (a path-less finding) its subtitle.
    fn place_text(&self, f: &Finding) -> String {
        match &f.path {
            Some(p) => format::home_relative(p, &self.home),
            None => f.subtitle.clone().unwrap_or_default(),
        }
    }

    /// The text of cell (`f`, `col_ix`) for the third to fifth columns, by layout.
    fn cell_text_of(&self, f: &Finding, col_ix: usize) -> Option<String> {
        let text = match (self.layout, col_ix) {
            (_, COL_NAME) => f.title.clone(),
            (Layout::Default, COL_THIRD) | (Layout::Versions, COL_FOURTH) => self.place_text(f),
            (Layout::Default, COL_FOURTH) => f
                .modified
                .map_or_else(|| "—".to_string(), |t| format::relative(t, self.now)),
            (Layout::Default, COL_FIFTH) => format::bytes(f.freed_if_deleted),
            (Layout::Apps, COL_THIRD) => source_text(f),
            (Layout::Apps, COL_FOURTH) => last_opened_text(f, self.now),
            (Layout::Apps, COL_FIFTH) | (Layout::Versions, COL_FIFTH) => format::bytes(f.allocated),
            (Layout::Versions, COL_THIRD) => status_text(f),
            _ => return None,
        };
        Some(text)
    }
}

/// A right-aligned value with an optional muted second line.
fn two_lines(cell: Div, top: String, below: Option<String>, muted: Hsla) -> AnyElement {
    cell.justify_end()
        .child(
            v_flex()
                .items_end()
                .child(top)
                .children(below.map(|b| div().text_xs().text_color(muted).truncate().child(b))),
        )
        .into_any_element()
}

impl TableDelegate for FindingsDelegate {
    fn columns_count(&self, _: &App) -> usize {
        5
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (first, second) = self.widths;
        let fixed = |key: &'static str, name: &'static str, width: f32| {
            Column::new(key, name).width(px(width))
        };
        match (self.layout, col_ix) {
            (_, COL_CHECK) => Column::new("check", "")
                .width(px(CHECK_WIDTH))
                .resizable(false)
                .selectable(false),
            (Layout::Versions, COL_NAME) => Column::new("name", "Name")
                .min_width(px(VERSION_NAME_MIN))
                .width(px(first)),
            (_, COL_NAME) => Column::new("name", "Name")
                .min_width(px(NAME_MIN))
                .width(px(first)),
            (Layout::Default, COL_THIRD) | (Layout::Versions, COL_FOURTH) => {
                Column::new("where", "Where")
                    .min_width(px(WHERE_MIN))
                    .width(px(second))
            }
            (Layout::Default, COL_FOURTH) => {
                fixed("modified", "Modified", MODIFIED_WIDTH).text_right()
            }
            (Layout::Default, _) => fixed("frees", "Frees", FREES_WIDTH).text_right(),
            (Layout::Apps, COL_THIRD) => fixed("source", "Source", SOURCE_WIDTH),
            (Layout::Apps, COL_FOURTH) => {
                fixed("last-opened", "Last opened", LAST_OPENED_WIDTH).text_right()
            }
            (Layout::Apps, _) => fixed("total", "Total", TOTAL_WIDTH).text_right(),
            (Layout::Versions, COL_THIRD) => fixed("status", "Status", STATUS_WIDTH),
            (Layout::Versions, _) => fixed("size", "Size", SIZE_WIDTH).text_right(),
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
        let mono = cx.theme().mono_font_family.clone();
        let cell = || h_flex().size_full().items_center().text_sm();
        match (self.layout, col_ix) {
            (_, COL_CHECK) => {
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
            (layout, COL_NAME) => {
                let (text, color) = badge(f.label, cx);
                let detail = match layout {
                    // A path-less finding (a model) shows its subtitle under Where instead.
                    Layout::Default => f.subtitle.clone().filter(|_| f.path.is_some()),
                    Layout::Apps => app_detail(f),
                    // The status has its own column.
                    Layout::Versions => None,
                };
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
                                detail
                                    .map(|s| div().text_xs().text_color(muted).truncate().child(s)),
                            ),
                    )
                    .into_any_element()
            }
            (Layout::Default, COL_THIRD) | (Layout::Versions, COL_FOURTH) => cell()
                .text_color(muted)
                .font_family(mono)
                .text_xs()
                .child(div().min_w_0().truncate().child(self.place_text(f)))
                .into_any_element(),
            (Layout::Default, COL_FOURTH) | (Layout::Apps, COL_FOURTH) => cell()
                .justify_end()
                .text_color(muted)
                .child(self.cell_text_of(f, col_ix).unwrap_or_default())
                .into_any_element(),
            (Layout::Default, COL_FIFTH) => {
                let frees = format::bytes(f.freed_if_deleted);
                let allocated = format::bytes(f.allocated);
                let below = (allocated != frees).then_some(allocated);
                two_lines(cell(), frees, below, muted)
            }
            (Layout::Apps, COL_THIRD) | (Layout::Versions, COL_THIRD) => cell()
                .text_color(muted)
                .child(
                    div()
                        .min_w_0()
                        .truncate()
                        .child(self.cell_text_of(f, col_ix).unwrap_or_default()),
                )
                .into_any_element(),
            (Layout::Apps, COL_FIFTH) => two_lines(
                cell(),
                format::bytes(f.allocated),
                total_breakdown(f),
                muted,
            ),
            (Layout::Versions, COL_FIFTH) => {
                two_lines(cell(), format::bytes(f.allocated), None, muted)
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
        self.cell_text_of(f, col_ix).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    // Explicit imports, like the crate's other test modules (see `app.rs`).
    use super::{
        FindingsDelegate, Layout, SortBy, filter, flex_widths, is_estimate, last_opened_text, sort,
        source_text, status_text, total_breakdown,
    };
    use crate::category::fixtures::{app, finding};
    use discky_core::findings::{AppSource, Component, ComponentKind, ComponentRemoval};
    use std::path::PathBuf;

    #[test]
    fn source_text_forms() {
        let cask = AppSource::Cask {
            token: "raycast".into(),
            full_token: "homebrew/cask/raycast".into(),
        };
        assert_eq!(source_text(&app("a", cask, Some(0), "")), "cask · raycast");
        let pkg = AppSource::Pkg {
            pkg_ids: vec!["us.zoom.pkg".into()],
        };
        assert_eq!(source_text(&app("b", pkg, Some(0), "")), "pkg");
        assert_eq!(
            source_text(&app("c", AppSource::AppStore, Some(0), "")),
            "App Store"
        );
        assert_eq!(
            source_text(&app("d", AppSource::Dragged, Some(0), "")),
            "drag & drop"
        );
        let mut group = finding("e", "Readdle", 1);
        group.rule_id = "app-leftovers".into();
        assert_eq!(source_text(&group), "leftovers");
        group.rule_id = "pkg-receipts".into();
        assert_eq!(source_text(&group), "receipts");
    }

    #[test]
    fn last_opened_text_marks_estimates() {
        let day = 86_400;
        let now = 400 * day;
        let exact = app(
            "a",
            AppSource::Dragged,
            Some(now - 3 * day),
            "drag & drop · last opened 3 days ago",
        );
        assert!(!is_estimate(&exact));
        assert_eq!(last_opened_text(&exact, now), "3 days ago");
        let estimate = app(
            "b",
            AppSource::Dragged,
            Some(now - 70 * day),
            "drag & drop · last opened 2 months ago*",
        );
        assert!(is_estimate(&estimate));
        assert_eq!(last_opened_text(&estimate, now), "2 months ago*");
        let never = app("c", AppSource::Dragged, None, "drag & drop · never opened*");
        assert_eq!(last_opened_text(&never, now), "never*");
        // A leftover group without a date is not an app that was never opened.
        let mut group = finding("d", "Readdle", 1);
        group.rule_id = "app-leftovers".into();
        group.modified = None;
        assert_eq!(last_opened_text(&group, now), "—");
    }

    #[test]
    fn versions_status_text() {
        let mut v = finding("n", "node 19.9.0", 1);
        v.subtitle = Some("global".into());
        assert_eq!(status_text(&v), "global");
        v.subtitle = Some("pinned in 3 projects · 2 untracked files".into());
        assert_eq!(status_text(&v), "pinned in 3 projects");
        v.subtitle = Some("not referenced".into());
        assert_eq!(status_text(&v), "not referenced");
        v.subtitle = None;
        assert_eq!(status_text(&v), "");
    }

    #[test]
    fn total_breakdown_splits_bundle_and_leftovers() {
        let component = |kind: ComponentKind, allocated: u64| Component {
            kind,
            title: String::new(),
            path: None,
            allocated,
            freed_if_deleted: allocated,
            modified: None,
            default_on: true,
            removal: ComponentRemoval::None,
            note: None,
            covered_by_cask: false,
        };
        let mut a = app("a", AppSource::Dragged, None, "");
        assert_eq!(total_breakdown(&a), None);
        a.components = vec![
            component(ComponentKind::AppBundle, 300_000_000),
            component(ComponentKind::Caches, 100_000_000),
        ];
        a.allocated = 400_000_000;
        assert_eq!(
            total_breakdown(&a).as_deref(),
            Some("app 300 MB + leftovers 100 MB")
        );
        a.allocated = 300_000_000;
        assert_eq!(total_breakdown(&a), None);
    }

    #[test]
    fn layout_follows_category() {
        use discky_core::rules::Category;
        assert_eq!(Layout::for_category(Category::Apps), Layout::Apps);
        assert_eq!(
            Layout::for_category(Category::LanguageVersions),
            Layout::Versions
        );
        assert_eq!(Layout::for_category(Category::DevCaches), Layout::Default);
    }

    #[test]
    fn sort_last_opened_puts_unknown_first() {
        let mut rows = vec![
            finding("a", "New", 1),
            finding("b", "Unknown", 2),
            finding("c", "Old", 3),
        ];
        rows[0].modified = Some(2_000);
        rows[1].modified = None;
        rows[2].modified = Some(1_000);
        sort(&mut rows, SortBy::LastOpened);
        assert_eq!(titles(&rows), ["Unknown", "Old", "New"]);
    }

    #[test]
    fn hidden_checked_counts_checked_rows_the_filter_hides() {
        let mut d = FindingsDelegate::new(Layout::Default, PathBuf::from("/Users/me"));
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
        let (name, place) = flex_widths(Layout::Default, 1_000.);
        assert!((name + place - (1_000. - 36. - 110. - 120. - 26.)).abs() < 0.01);
        assert!(name > place);
        assert_eq!(flex_widths(Layout::Default, 300.), (240., 200.));
        let (name, _) = flex_widths(Layout::Apps, 1_000.);
        assert!((name - (1_000. - 36. - 130. - 120. - 180. - 26.)).abs() < 0.01);
        assert_eq!(flex_widths(Layout::Apps, 300.).0, 240.);
        let (name, place) = flex_widths(Layout::Versions, 1_000.);
        assert!((name + place - (1_000. - 36. - 180. - 120. - 26.)).abs() < 0.01);
        assert_eq!(flex_widths(Layout::Versions, 300.), (200., 200.));
    }
}
