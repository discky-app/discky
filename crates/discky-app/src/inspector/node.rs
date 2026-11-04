//! The inspector's path subject: a disk-map tile without a finding of its own. Its rows
//! and removal button state are built here, free of GPUI ([`path_rows`]); the planner
//! (`Engine::plan_paths`) stays the authority on what is removed.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use discky_core::findings::{FindingId, Removal};
use discky_core::fs::attr::ObjKind;
use discky_core::index::NodeFlags;
use discky_core::plan::{
    CLOUD_REFUSED, NOT_IN_SNAPSHOT, PROTECTED_REFUSED, ROOT_REFUSED, is_protected, managed_by,
};
use discky_core::query::NodeFindings;
use discky_core::rules::Category;
use discky_core::{Engine, Inspection, RemovalMode};

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use super::{Inspector, InspectorEvent, meta_row, path_link, show_in_button};
use crate::app::AppState;
use crate::format;

/// The flag [`inspect_path`] adds to a scan root's entry (`TreeEntry::flags` has none).
pub const ROOT_FLAG: &str = "root";
/// The flag of an entry stored in the cloud, not on disk.
const DATALESS_FLAG: &str = "dataless";

/// What the inspector shows for a path, and whether it offers to remove it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRows {
    /// "Path" (home-relative), "On disk", "Claimed" (when it differs), "Frees", "Files"
    /// (folders), "Modified", "Flags", "App", "Category", "Rule": those that apply.
    pub rows: Vec<(&'static str, String)>,
    /// The finding owning the path (its own or an ancestor's): category, id, title.
    pub managed_by: Option<(Category, FindingId, String)>,
    /// "Move to Trash…" or "Delete permanently…", by the removal mode.
    pub remove_label: &'static str,
    pub can_remove: bool,
    /// Why the path cannot be removed (the planner's refusal text), when `!can_remove`.
    pub remove_reason: Option<String>,
}

/// The rows and the removal button state for the path of `insp` (see [`inspect_path`]):
/// removal is refused, in the planner's order, for a path not in the snapshot, a scan root,
/// a dataless entry, a protected location (also every path when `home` is unknown), and a
/// path owned by a finding whose removal is not a plain trash. The planner's other rule
/// (a folder containing such a finding) shows up as a skipped step in the dialog.
/// `now` is Unix seconds.
pub fn path_rows(insp: &Inspection, mode: RemovalMode, home: &Path, now: i64) -> PathRows {
    let mut rows = Vec::new();
    if let Some(e) = &insp.entry {
        rows.push(("Path", format::home_relative(&e.path, home)));
        rows.push(("On disk", format::bytes(e.allocated)));
        if e.logical != e.allocated {
            rows.push(("Claimed", format::bytes(e.logical)));
        }
        rows.push(("Frees", format::bytes(e.freed_if_deleted)));
        if e.kind == ObjKind::Dir {
            rows.push(("Files", format::count(u64::from(e.files))));
        }
        if e.modified > 0 {
            rows.push((
                "Modified",
                format!(
                    "{} · {}",
                    format::when(e.modified),
                    format::relative(e.modified, now)
                ),
            ));
        }
        if !e.flags.is_empty() {
            rows.push(("Flags", e.flags.join(", ")));
        }
    }
    if let Some(app) = &insp.owner_app {
        rows.push(("App", app.clone()));
    }
    if let Some(f) = &insp.finding {
        rows.push(("Category", format!("{} · {}", f.category, f.title)));
    }
    if let Some((title, _)) = &insp.rule {
        rows.push(("Rule", title.clone()));
    }
    let has_flag = |flag: &str| {
        insp.entry
            .as_ref()
            .is_some_and(|e| e.flags.iter().any(|f| f == flag))
    };
    let remove_reason = match (&insp.entry, &insp.finding) {
        (None, _) => Some(NOT_IN_SNAPSHOT.to_string()),
        _ if !insp.in_snapshot => Some(NOT_IN_SNAPSHOT.to_string()),
        _ if has_flag(ROOT_FLAG) => Some(ROOT_REFUSED.to_string()),
        _ if has_flag(DATALESS_FLAG) => Some(CLOUD_REFUSED.to_string()),
        (Some(e), _) if is_protected(&e.path, home) => Some(PROTECTED_REFUSED.to_string()),
        (_, Some(f)) if !matches!(f.removal, Removal::Trash { .. }) => Some(managed_by(f.category)),
        _ => None,
    };
    PathRows {
        rows,
        managed_by: insp
            .finding
            .as_ref()
            .map(|f| (f.category, f.id.clone(), f.title.clone())),
        remove_label: match mode {
            RemovalMode::Trash => "Move to Trash…",
            RemovalMode::Permanent => "Delete permanently…",
        },
        can_remove: remove_reason.is_none(),
        remove_reason,
    }
}

/// `Engine::inspect` of `path`, completed for the path subject: when the path is no
/// finding's own, `finding` is the finding owning it through an ancestor (as the disk map
/// colours it, `query::NodeFindings`), and a scan root's entry carries [`ROOT_FLAG`].
/// `None` without a snapshot.
pub fn inspect_path(engine: &Engine, path: &Path) -> Option<Inspection> {
    let mut insp = engine.inspect(&path.to_string_lossy())?;
    let Some(snap) = engine.snapshot() else {
        return Some(insp);
    };
    let Some(node) = path.is_absolute().then(|| snap.index.find(path)).flatten() else {
        return Some(insp);
    };
    if insp.finding.is_none() {
        insp.finding = NodeFindings::build(&snap)
            .owner(&snap.index, node)
            .map(|i| snap.findings[i].clone());
    }
    if snap.index.node(node).flags.contains(NodeFlags::ROOT)
        && let Some(e) = &mut insp.entry
    {
        e.flags.push(ROOT_FLAG.to_string());
    }
    Some(insp)
}

/// The inspector's title for `path`: its file name (the path itself for `/`).
pub fn title(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

impl Inspector {
    /// [`path_rows`] of the loaded inspection; `None` until it is loaded.
    pub(super) fn path_rows(&self, cx: &App) -> Option<PathRows> {
        let insp = self.inspection.as_ref()?;
        let mode = cx.global::<AppState>().engine.config().removal.mode;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        Some(path_rows(insp, mode, &self.home, now))
    }

    /// The rows (the Path row reveals `path` in Finder), then "Contents · top N".
    pub(super) fn path_body(
        &self,
        path: &Path,
        rows: Option<&PathRows>,
        cx: &App,
    ) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, mono) = (theme.muted_foreground, theme.mono_font_family.clone());
        let Some(rows) = rows else {
            return div()
                .text_sm()
                .text_color(muted)
                .child("Preparing…")
                .into_any_element();
        };
        let meta = rows.rows.iter().map(|(label, value)| {
            let value = if *label == "Path" {
                path_link(path.to_path_buf(), value.clone(), mono.clone()).into_any_element()
            } else {
                value.clone().into_any_element()
            };
            meta_row(label, value, muted)
        });
        v_flex()
            .child(v_flex().gap_2().children(meta))
            .children(self.contents(cx))
            .into_any_element()
    }

    /// The bottom bar: why the path cannot be removed (also the remove button's tooltip),
    /// "Show in Finder", "Show in {category}" when a finding owns it, and the remove button.
    pub(super) fn path_footer(
        &self,
        path: &Path,
        rows: Option<&PathRows>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);
        let reason = rows.and_then(|r| r.remove_reason.clone());
        let can_remove = rows.is_some_and(|r| r.can_remove);
        let label = rows.map_or("Move to Trash…", |r| r.remove_label);
        let show_in = rows
            .and_then(|r| r.managed_by.clone())
            .map(|(category, id, _)| show_in_button(category, id, cx));
        let reveal: PathBuf = path.to_path_buf();
        let remove: PathBuf = path.to_path_buf();
        h_flex()
            .flex_shrink_0()
            .gap_2()
            .px_4()
            .py_2()
            .border_t_1()
            .border_color(border)
            .items_center()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_xs()
                    .text_color(muted)
                    .children(reason.clone()),
            )
            .child(
                Button::new("inspector-reveal")
                    .small()
                    .label("Show in Finder")
                    .on_click(move |_, _, cx| cx.reveal_path(&reveal)),
            )
            .children(show_in)
            .child(
                Button::new("inspector-remove-path")
                    .small()
                    .danger()
                    .label(label)
                    .disabled(!can_remove)
                    .when_some(reason, |this, reason| this.tooltip(reason))
                    .on_click(cx.listener(move |_, _, _, cx| {
                        cx.emit(InspectorEvent::RemovePaths(vec![remove.clone()]));
                    })),
            )
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use discky_core::findings::{Finding, FindingId, Removal};
    use discky_core::fs::attr::ObjKind;
    use discky_core::plan;
    use discky_core::query::TreeEntry;
    use discky_core::rules::{Category, SafetyLabel};
    use discky_core::{Inspection, RemovalMode};

    use super::path_rows;

    const HOME: &str = "/Users/me";
    const NOW: i64 = 1_800_000_000;

    fn entry(path: &str, allocated: u64, logical: u64) -> TreeEntry {
        let path = PathBuf::from(path);
        TreeEntry {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            path,
            kind: ObjKind::Dir,
            allocated,
            logical,
            freed_if_deleted: allocated,
            files: 3,
            modified: NOW - 86_400,
            flags: Vec::new(),
            finding: None,
        }
    }

    fn inspection(entry: TreeEntry, finding: Option<Finding>) -> Inspection {
        Inspection {
            finding,
            entry: Some(entry),
            children: Vec::new(),
            rule: None,
            owner_app: None,
            in_snapshot: true,
        }
    }

    fn finding(category: Category, path: &str, removal: Removal) -> Finding {
        let path = PathBuf::from(path);
        Finding {
            id: FindingId::for_path(&path),
            category,
            title: "Cache".to_string(),
            subtitle: None,
            path: Some(path),
            node: None,
            allocated: 4096,
            logical: 4096,
            freed_if_deleted: 4096,
            modified: None,
            label: SafetyLabel::Regenerates,
            rule_id: "test".to_string(),
            explain: String::new(),
            removal,
            flags: Vec::new(),
            components: Vec::new(),
        }
    }

    #[test]
    fn rows_for_a_plain_folder() {
        let insp = inspection(entry("/Users/me/Projects/notes", 8192, 8192), None);
        let rows = path_rows(&insp, RemovalMode::Trash, Path::new(HOME), NOW);
        let labels: Vec<&str> = rows.rows.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["Path", "On disk", "Frees", "Files", "Modified"]);
        assert_eq!(rows.rows[0].1, "~/Projects/notes");
        assert_eq!(rows.rows[3].1, "3");
        assert!(rows.managed_by.is_none());
        assert!(rows.can_remove);
        assert_eq!(rows.remove_reason, None);
        assert_eq!(rows.remove_label, "Move to Trash…");
        let permanent = path_rows(&insp, RemovalMode::Permanent, Path::new(HOME), NOW);
        assert_eq!(permanent.remove_label, "Delete permanently…");
        assert!(permanent.can_remove);
    }

    #[test]
    fn managed_folder_disables_removal_with_reason() {
        let f = finding(
            Category::DevCaches,
            "/Users/me/.cargo/registry",
            Removal::Command {
                tool: "cargo".to_string(),
                argv: vec!["cargo".to_string(), "cache".to_string()],
                cwd: None,
                install_hint: None,
                freed_note: None,
            },
        );
        let id = f.id.clone();
        let insp = inspection(
            entry("/Users/me/.cargo/registry/cache", 8192, 4096),
            Some(f),
        );
        let rows = path_rows(&insp, RemovalMode::Trash, Path::new(HOME), NOW);
        assert_eq!(
            rows.managed_by,
            Some((Category::DevCaches, id, "Cache".to_string()))
        );
        assert!(!rows.can_remove);
        assert_eq!(
            rows.remove_reason,
            Some(plan::managed_by(Category::DevCaches))
        );
        let claimed = rows.rows.iter().find(|(l, _)| *l == "Claimed");
        assert!(claimed.is_some(), "logical differs from allocated");
        let category = rows.rows.iter().find(|(l, _)| *l == "Category").unwrap();
        assert_eq!(category.1, "Dev caches · Cache");
    }

    #[test]
    fn trash_managed_folder_stays_removable() {
        let path = "/Users/me/Projects/app/target";
        let f = finding(
            Category::ProjectBuilds,
            path,
            Removal::Trash {
                paths: vec![PathBuf::from(path)],
            },
        );
        let insp = inspection(
            entry("/Users/me/Projects/app/target/debug", 8192, 8192),
            Some(f),
        );
        let rows = path_rows(&insp, RemovalMode::Trash, Path::new(HOME), NOW);
        assert!(rows.managed_by.is_some());
        assert!(rows.can_remove);
        assert_eq!(rows.remove_reason, None);
    }
}
