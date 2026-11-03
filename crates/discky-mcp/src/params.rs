//! Tool parameters and outputs. Doc comments become the JSON-schema descriptions agents
//! read, so they are written for them.
//!
//! Core types that carry no `JsonSchema` (findings, statuses, history records…) are
//! embedded with an "any JSON" schema; their shape is described in the field docs.

use std::collections::HashMap;
use std::path::PathBuf;

use discky_core::findings::{Component, ComponentRemoval, Finding, Removal};
use discky_core::fs::attr::ObjKind;
use discky_core::query::TreeEntry;
use discky_core::rules::{Category, SafetyLabel};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn category_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": ["string", "null"],
        "enum": ["apps", "app_caches", "models", "dev_caches", "project_builds",
                 "language_versions", "large_old", null]
    })
}

fn label_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": ["string", "null"],
        "enum": ["regenerates", "app_data", "needs_password", "app_running", "do_not_touch", null]
    })
}

fn kind_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": ["string", "null"],
        "enum": ["File", "Dir", "Symlink", "Other", null]
    })
}

/// A core type passed through as-is with an object schema.
#[derive(Serialize)]
#[serde(transparent)]
pub struct Obj<T>(pub T);

impl<T> JsonSchema for Obj<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Object".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "object" })
    }
}

/// `bytes` as a human-readable size, base 1024 with one decimal: `"512 B"`, `"14.0 GB"`.
pub fn human_size(bytes: u64) -> String {
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

// ---- Parameters -------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Absolute directories to scan (a leading `~` is expanded). Omit to scan the roots
    /// configured in Discky.
    pub roots: Option<Vec<String>>,
    /// Seconds to wait for the scan to finish before returning, 0 to 60 (default 0 =
    /// return at once and poll `scan_status`).
    pub wait_seconds: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanStatusParams {
    /// The `scan_id` returned by `scan`.
    pub scan_id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct FindingsParams {
    /// Only this category.
    #[schemars(schema_with = "category_schema")]
    pub category: Option<Category>,
    /// Only this safety label (`regenerates` = safe, comes back on its own).
    #[schemars(schema_with = "label_schema")]
    pub label: Option<SafetyLabel>,
    /// Only findings with at least this many allocated bytes.
    pub min_bytes: Option<u64>,
    /// Only findings not modified for this many days.
    pub older_than_days: Option<u32>,
    /// Skip this many findings (for paging; default 0).
    pub offset: Option<usize>,
    /// Page size, default 25, at most 200.
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TreeParams {
    /// Absolute path of a directory in the last snapshot.
    pub path: String,
    /// How many children to return, largest first (default 20, at most 200).
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Glob matched against entry names, e.g. `"*.dmg"`.
    pub name_glob: Option<String>,
    /// Only entries with at least this many allocated bytes.
    pub min_bytes: Option<u64>,
    /// Only entries not modified for this many days.
    pub older_than_days: Option<u32>,
    /// Only this kind of entry.
    #[schemars(schema_with = "kind_schema")]
    pub kind: Option<ObjKind>,
    /// Only entries below this absolute path.
    pub under: Option<PathBuf>,
    /// At most this many results, largest first (default 50, at most 200).
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectParams {
    /// A finding id, an absolute path in the snapshot, or an app / finding title.
    pub target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanParams {
    /// Ids of the findings to remove, from `findings` or `inspect`.
    pub finding_ids: Vec<String>,
    /// Finding id → component indices to remove; omitted ids use their default
    /// components. Indices come from `inspect` (`components[].index`).
    #[serde(default)]
    pub components: Option<HashMap<String, Vec<usize>>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteParams {
    /// The `id` returned by `plan_removal`.
    pub plan_id: String,
    /// Run only these step indices; omit to run every step.
    pub only_steps: Option<Vec<usize>>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct HistoryParams {
    /// At most this many records, newest first (default 50).
    pub limit: Option<usize>,
}

// ---- Outputs ----------------------------------------------------------------

/// Disk usage summary from the last snapshot.
#[derive(Debug, Serialize, JsonSchema)]
pub struct OverviewOut {
    /// The data volume: `{mount, total, used, available}` in bytes.
    #[schemars(with = "Value")]
    pub volume: discky_core::query::VolumeInfo,
    /// Unix seconds of the last scan; null when nothing was scanned yet.
    pub snapshot_at: Option<i64>,
    /// Who ran the last scan: `"app"` or `"mcp"`.
    #[schemars(with = "Option<String>")]
    pub actor: Option<discky_core::index::snapshot::Actor>,
    /// Bytes allocated on disk under the scanned roots.
    pub scanned_allocated: u64,
    /// `[[category, bytes], ...]`: allocated bytes per category, over findings not
    /// labelled `do_not_touch`.
    #[schemars(with = "Value")]
    pub by_category: Vec<(Category, u64)>,
    /// Allocated bytes of findings labelled `do_not_touch` (in no category).
    pub protected_bytes: u64,
    /// Bytes freed by removing everything labelled `regenerates`, except commands that
    /// free only part of their finding (those with a `freed_note`).
    pub safe_to_free: u64,
    /// Directories the scan could not read.
    pub no_access: usize,
    /// Whether `freed_if_deleted` was measured exactly (true) or clone-aware only
    /// (false); null without a snapshot.
    pub exact_private_size: Option<bool>,
    /// Seconds since the last scan; null without one.
    pub snapshot_age_seconds: Option<u64>,
    /// True when there is no snapshot or it is older than one hour: call `scan`.
    pub stale: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ScanOut {
    /// Pass to `scan_status`.
    pub scan_id: String,
    /// `{kind: "running" | "done" | "failed" | "cancelled" | "unknown", ...}`; `running`
    /// carries `progress {files, dirs, allocated, current}`, `done` carries `node_count`,
    /// `findings`, `duration_ms`; `cancelled` carries `duration_ms`.
    #[schemars(with = "Value")]
    pub status: discky_core::ScanStatus,
}

/// A finding: something removable with an honest size, a safety label and a method.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FindingOut {
    /// Stable id: pass to `inspect` and `plan_removal`.
    pub id: String,
    #[schemars(with = "String")]
    pub category: Category,
    pub title: String,
    pub subtitle: Option<String>,
    pub path: Option<PathBuf>,
    /// Bytes allocated on disk.
    pub allocated: u64,
    /// Logical (apparent) size in bytes.
    pub logical: u64,
    /// Bytes deletion really frees (clones and hard links shared elsewhere excluded).
    pub freed_if_deleted: u64,
    /// `allocated`, human-readable.
    pub human_size: String,
    /// Unix seconds of the newest modification inside.
    pub modified: Option<i64>,
    /// `regenerates`, `app_data`, `needs_password`, `app_running` or `do_not_touch`.
    #[schemars(with = "String")]
    pub label: SafetyLabel,
    pub rule_id: String,
    /// Why this is removable and what happens if it is removed.
    pub explain: String,
    /// `trash`, `command`, `ollama_delete`, `app`, `mise_uninstall` or `none` (never
    /// removed by Discky).
    pub removal_kind: String,
    /// Removal details, e.g. `{"trash": {"paths": [...]}}` or `{"command": {"argv": [...]}}`.
    #[schemars(with = "Value")]
    pub removal: Removal,
    /// Any of `sparse`, `dataless`, `hardlinks`, `no_access`, `clone_shared`.
    pub flags: Vec<String>,
    /// Number of removable parts (`findings` rows only; `inspect` lists them in
    /// `components`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components_count: Option<usize>,
    /// Parts of an Applications or Language versions finding that `plan_removal` can
    /// include or leave out (`inspect` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentOut>>,
}

/// One removable part of a finding (an app's bundle or a leftover, a project requesting
/// a tool version).
#[derive(Debug, Serialize, JsonSchema)]
pub struct ComponentOut {
    /// Pass in `plan_removal`'s `components`.
    pub index: usize,
    /// `app_bundle`, `application_support`, `caches`, `preferences`, `container`,
    /// `group_container`, `saved_state`, `http_storage`, `web_kit`, `cookies`, `logs`,
    /// `launch_agent`, `launch_daemon`, `application_script`, `privileged_helper`,
    /// `receipt`, `own_uninstaller`, `project` or `other`.
    pub kind: String,
    pub title: String,
    pub path: Option<String>,
    pub allocated: u64,
    pub human_size: String,
    pub freed_if_deleted: u64,
    /// Included when `plan_removal` gets no `components` for the finding.
    pub default_on: bool,
    /// `trash`, `defaults`, `bootout`, `pkg_forget`, `run_script` (the vendor's uninstaller,
    /// run as the user from Discky.app only) or `none` (shown only; refused when selected).
    pub removal: String,
    /// E.g. "needs administrator password", "shared with Google Drive".
    pub note: Option<String>,
    /// Removed by `brew uninstall --zap`; no separate step is planned.
    pub covered_by_cask: bool,
}

impl ComponentOut {
    fn new(index: usize, c: Component) -> ComponentOut {
        let kind = serde_json::to_value(&c.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{:?}", c.kind).to_lowercase());
        let removal = match c.removal {
            ComponentRemoval::Trash => "trash",
            ComponentRemoval::Defaults { .. } => "defaults",
            ComponentRemoval::Bootout { .. } => "bootout",
            ComponentRemoval::PkgForget { .. } => "pkg_forget",
            ComponentRemoval::RunScript => "run_script",
            ComponentRemoval::None => "none",
        };
        ComponentOut {
            index,
            kind,
            title: c.title,
            path: c.path.map(|p| p.to_string_lossy().into_owned()),
            allocated: c.allocated,
            human_size: human_size(c.allocated),
            freed_if_deleted: c.freed_if_deleted,
            default_on: c.default_on,
            removal: removal.to_string(),
            note: c.note,
            covered_by_cask: c.covered_by_cask,
        }
    }
}

impl FindingOut {
    /// `with_components`: list the components (`inspect`) instead of only counting them
    /// (`findings`).
    pub fn new(f: Finding, with_components: bool) -> FindingOut {
        let removal_kind = match &f.removal {
            Removal::Trash { .. } => "trash",
            Removal::Command { .. } => "command",
            Removal::OllamaDelete { .. } => "ollama_delete",
            Removal::App { .. } => "app",
            Removal::MiseUninstall { .. } => "mise_uninstall",
            Removal::None => "none",
        };
        let count = f.components.len();
        let (components_count, components) = if with_components {
            let list = f
                .components
                .into_iter()
                .enumerate()
                .map(|(i, c)| ComponentOut::new(i, c))
                .collect();
            (None, Some(list))
        } else {
            (Some(count), None)
        };
        FindingOut {
            id: f.id.0,
            category: f.category,
            title: f.title,
            subtitle: f.subtitle,
            path: f.path,
            allocated: f.allocated,
            logical: f.logical,
            freed_if_deleted: f.freed_if_deleted,
            human_size: human_size(f.allocated),
            modified: f.modified,
            label: f.label,
            rule_id: f.rule_id,
            explain: f.explain,
            removal_kind: removal_kind.to_string(),
            removal: f.removal,
            flags: f.flags,
            components_count,
            components,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FindingsOut {
    /// Largest `freed_if_deleted` first.
    pub items: Vec<FindingOut>,
    /// Matching findings in all pages.
    pub total: usize,
    pub offset: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EntriesOut {
    /// Largest first. Each entry: `{name, path, kind, allocated, logical,
    /// freed_if_deleted, files, modified, flags, finding}` (`finding` = id or null).
    #[schemars(with = "Value")]
    pub entries: Vec<TreeEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InspectOut {
    /// The finding the target resolved to, if any.
    pub finding: Option<FindingOut>,
    /// The target's own tree entry, if it is in the snapshot.
    #[schemars(with = "Value")]
    pub entry: Option<TreeEntry>,
    /// Largest children first, at most 20.
    #[schemars(with = "Value")]
    pub children: Vec<TreeEntry>,
    /// `[title, explanation]` of the rule that matched.
    pub rule: Option<(String, String)>,
    pub owner_app: Option<String>,
    pub in_snapshot: bool,
}

/// A removal plan. Nothing has been removed yet.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PlanOut {
    /// Pass to `execute_plan`.
    pub id: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Bytes the plan frees.
    pub total_freed: u64,
    /// `total_freed`, human-readable.
    pub human_total: String,
    /// Ordered steps: `{index, finding, description, kind, freed, freed_note, flags,
    /// warnings, ...}`; `kind` is `quit`, `trash`, `remove`, `command` or
    /// `ollama_delete`; the `interactive` flag means only Discky.app can run it.
    #[schemars(with = "Value")]
    pub steps: Value,
    /// Findings not planned: `[{finding, reason}]`.
    #[schemars(with = "Value")]
    pub skipped: Value,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SkippedStep {
    pub index: usize,
    pub description: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecuteOut {
    pub plan: String,
    /// One per step: `{index, status: "done"|"failed"|"skipped"|"not_run", output,
    /// freed, reason}`.
    #[schemars(with = "Value")]
    pub results: Vec<discky_core::plan::execute::StepResult>,
    /// Bytes freed (including bytes moved to the Trash).
    pub freed_total: u64,
    /// Part of `freed_total` still in the Trash until it is emptied.
    pub trashed_bytes: u64,
    /// Index of the step that failed and stopped the plan.
    pub stopped_at: Option<usize>,
    pub log_path: PathBuf,
    /// Steps that need the user (admin prompt or quitting an app): run them from
    /// Discky.app.
    pub skipped_interactive: Vec<SkippedStep>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TrashItem {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HistoryOut {
    /// Executed steps, newest first: `{ts, actor, plan, step, kind, paths, argv, status,
    /// freed, output_tail, trash_paths, reason}`.
    #[schemars(with = "Value")]
    pub records: Vec<discky_core::history::HistoryRecord>,
    /// Items Discky moved to the Trash that are still there.
    pub in_trash: Vec<TrashItem>,
    /// Bytes still held in the Trash by those items.
    pub trash_total: u64,
}

#[cfg(test)]
mod tests {
    use super::human_size;

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(14 * 1024 * 1024 * 1024), "14.0 GB");
    }
}
