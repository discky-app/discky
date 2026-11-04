//! The inspector's path subject: a disk-map tile without a finding of its own. Its rows
//! and removal button state are built here, free of GPUI ([`path_rows`]); whether the
//! path can be removed is the planner's own verdict (`plan::path_refusal`).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use discky_core::findings::FindingId;
use discky_core::fs::attr::ObjKind;
use discky_core::plan::{NOT_IN_SNAPSHOT, PROTECTED_REFUSED, path_refusal};
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

/// The rows and the removal button state for the path of `insp`; `refusal` is the
/// planner's verdict on it (see [`inspect_path`]). Removal is refused for a path not in
/// the snapshot, for every path when `home` is unknown ([`PROTECTED_REFUSED`]), and with
/// `refusal` otherwise. `now` is Unix seconds.
pub fn path_rows(
    insp: &Inspection,
    refusal: Option<&str>,
    mode: RemovalMode,
    home: &Path,
    now: i64,
) -> PathRows {
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
    let remove_reason = if insp.entry.is_none() || !insp.in_snapshot {
        Some(NOT_IN_SNAPSHOT)
    } else if !home.is_absolute() {
        Some(PROTECTED_REFUSED)
    } else {
        refusal
    }
    .map(str::to_string);
    PathRows {
        rows,
        managed_by: insp
            .finding
            .as_ref()
            .map(|f| (f.category, f.id.clone(), f.title.clone())),
        remove_label: remove_label(mode),
        can_remove: remove_reason.is_none(),
        remove_reason,
    }
}

/// "Move to Trash…" or "Delete permanently…".
pub fn remove_label(mode: RemovalMode) -> &'static str {
    match mode {
        RemovalMode::Trash => "Move to Trash…",
        RemovalMode::Permanent => "Delete permanently…",
    }
}

/// `Engine::inspect` of `path`, completed for the path subject, with the planner's
/// refusal of it (`plan::path_refusal` against `home`; `None` when it can be removed or is
/// not in the snapshot). When the path is no finding's own, `finding` is the finding owning
/// it through an ancestor (as the disk map colours it, `query::NodeFindings`). `None`
/// without a snapshot.
pub fn inspect_path(
    engine: &Engine,
    path: &Path,
    home: &Path,
) -> Option<(Inspection, Option<String>)> {
    let mut insp = engine.inspect(&path.to_string_lossy())?;
    let Some(snap) = engine.snapshot() else {
        return Some((insp, None));
    };
    let Some(node) = path.is_absolute().then(|| snap.index.find(path)).flatten() else {
        return Some((insp, None));
    };
    let findings = NodeFindings::build(&snap);
    if insp.finding.is_none() {
        insp.finding = findings
            .owner(&snap.index, node)
            .map(|i| snap.findings[i].clone());
    }
    let refusal = path_refusal(&snap, &findings, node, home);
    Some((insp, refusal))
}

/// The inspector's title for `path`: its file name (the path itself for `/`).
pub fn title(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

impl Inspector {
    /// [`path_rows`] of the loaded inspection; `None` while it loads or when it could not
    /// be inspected (no snapshot).
    pub(super) fn path_rows(&self, mode: RemovalMode) -> Option<PathRows> {
        let insp = self.inspection.as_ref()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        Some(path_rows(
            insp,
            self.refusal.as_deref(),
            mode,
            &self.home,
            now,
        ))
    }

    /// The removal mode of the current config.
    pub(super) fn removal_mode(cx: &App) -> RemovalMode {
        cx.global::<AppState>().engine.config().removal.mode
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
            let text = if self.loading {
                "Preparing…"
            } else {
                NOT_IN_SNAPSHOT
            };
            return div()
                .text_sm()
                .text_color(muted)
                .child(text)
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
        mode: RemovalMode,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);
        let reason = match rows {
            Some(r) => r.remove_reason.clone(),
            None if !self.loading => Some(NOT_IN_SNAPSHOT.to_string()),
            None => None,
        };
        let can_remove = rows.is_some_and(|r| r.can_remove);
        let label = remove_label(mode);
        let show_in = rows
            .and_then(|r| r.managed_by.clone())
            .map(|(category, id, _)| show_in_button(category, id, cx));
        let reveal: PathBuf = path.to_path_buf();
        let remove: PathBuf = path.to_path_buf();
        let buttons = h_flex()
            .flex_wrap()
            .justify_end()
            .items_center()
            .gap_2()
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
                    .when_some(reason.clone(), |this, reason| this.tooltip(reason))
                    .on_click(cx.listener(move |_, _, _, cx| {
                        cx.emit(InspectorEvent::RemovePaths(vec![remove.clone()]));
                    })),
            );
        v_flex()
            .flex_shrink_0()
            .gap_1()
            .px_4()
            .py_2()
            .border_t_1()
            .border_color(border)
            .children(reason.map(|r| div().text_xs().text_color(muted).child(r)))
            .child(buttons)
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
        let rows = path_rows(&insp, None, RemovalMode::Trash, Path::new(HOME), NOW);
        let labels: Vec<&str> = rows.rows.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["Path", "On disk", "Frees", "Files", "Modified"]);
        assert_eq!(rows.rows[0].1, "~/Projects/notes");
        assert_eq!(rows.rows[3].1, "3");
        assert!(rows.managed_by.is_none());
        assert!(rows.can_remove);
        assert_eq!(rows.remove_reason, None);
        assert_eq!(rows.remove_label, "Move to Trash…");
        let permanent = path_rows(&insp, None, RemovalMode::Permanent, Path::new(HOME), NOW);
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
        let managed = plan::managed_by(Category::DevCaches);
        let insp = inspection(
            entry("/Users/me/.cargo/registry/cache", 8192, 4096),
            Some(f),
        );
        let rows = path_rows(
            &insp,
            Some(&managed),
            RemovalMode::Trash,
            Path::new(HOME),
            NOW,
        );
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
        let rows = path_rows(&insp, None, RemovalMode::Trash, Path::new(HOME), NOW);
        assert!(rows.managed_by.is_some());
        assert!(rows.can_remove);
        assert_eq!(rows.remove_reason, None);
    }

    /// The removal reason `path_rows` gives a plain folder with `refusal` and `home`.
    fn reason(refusal: Option<&str>, home: &str) -> Option<String> {
        let insp = inspection(entry("/Users/me/Projects/notes", 8192, 8192), None);
        let rows = path_rows(&insp, refusal, RemovalMode::Trash, Path::new(home), NOW);
        assert_eq!(rows.can_remove, rows.remove_reason.is_none());
        rows.remove_reason
    }

    #[test]
    fn planner_refusals_disable_removal() {
        for refusal in [
            plan::ROOT_REFUSED.to_string(),
            plan::CLOUD_REFUSED.to_string(),
            plan::PROTECTED_REFUSED.to_string(),
            plan::managed_by(Category::DevCaches),
        ] {
            assert_eq!(reason(Some(&refusal), HOME), Some(refusal));
        }
    }

    #[test]
    fn a_path_not_in_the_snapshot_cannot_be_removed() {
        let mut insp = inspection(entry("/Users/me/gone", 1, 1), None);
        insp.in_snapshot = false;
        let rows = path_rows(&insp, None, RemovalMode::Trash, Path::new(HOME), NOW);
        assert_eq!(rows.remove_reason.as_deref(), Some(plan::NOT_IN_SNAPSHOT));
        insp.entry = None;
        let rows = path_rows(&insp, None, RemovalMode::Trash, Path::new(HOME), NOW);
        assert!(!rows.can_remove);
        assert!(rows.rows.is_empty());
    }

    #[test]
    fn unknown_home_protects_every_path() {
        assert_eq!(reason(None, "").as_deref(), Some(plan::PROTECTED_REFUSED));
    }
}
