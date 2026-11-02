//! Pass 3: large files, directories untouched for a long time, and `~/Downloads`.

use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Thresholds;
use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Category, SafetyLabel};

use super::{Finding, node_finding, walk_unclaimed};

const DAY: i64 = 24 * 3600;

/// `LargeOld` findings for what earlier passes left unclaimed, outside `~/Library`:
///
/// - files whose `logical` **or** `allocated` size exceeds `large_file_bytes`. Logical
///   counts too: a sparse file that claims far more than it occupies is worth showing,
///   and its `"sparse"` flag and honest `allocated`/`freed_if_deleted` tell the user
///   that deleting it frees little;
/// - the topmost directories whose newest mtime is older than `old_days`;
/// - every direct child of `~/Downloads`, subtitled "Downloads".
///
/// A directory that contains a claimed node (a build dir, a `DoNotTouch` rule match, …)
/// is never reported as a whole — the walk descends into it instead — so sizes are not
/// counted twice and protected subtrees are never trashed with their parent. Scan roots,
/// `$HOME` and `~/Downloads` itself are never reported. Every finding claims its node.
pub fn find(
    index: &Index,
    thresholds: &Thresholds,
    home: Option<&Path>,
    claimed: &mut HashSet<NodeId>,
) -> Vec<Finding> {
    let cutoff = now() - i64::from(thresholds.old_days) * DAY;
    let library = home.map(|h| h.join("Library"));
    let downloads = home.map(|h| h.join("Downloads"));
    let contains_claimed = ancestors_of(index, claimed);

    let mut out = Vec::new();
    let mut hits = Vec::new();
    walk_unclaimed(index, claimed, |id, path| {
        if library.as_deref().is_some_and(|l| path.starts_with(l)) {
            return false;
        }
        let node = index.node(id);
        let is_dir = node.kind == ObjKind::Dir;
        if node.parent.is_none()
            || Some(path) == home
            || Some(path) == downloads.as_deref()
            || contains_claimed.contains(&id)
        {
            return is_dir;
        }
        let (rule_id, explain, subtitle) = if path.parent() == downloads.as_deref() {
            ("downloads", DOWNLOADS, Some("Downloads"))
        } else if is_dir && node.max_mtime < cutoff {
            ("old-dir", OLD_DIR, None)
        } else if node.kind == ObjKind::File
            && (node.logical > thresholds.large_file_bytes
                || node.allocated > thresholds.large_file_bytes)
        {
            ("large-file", LARGE_FILE, None)
        } else {
            return is_dir;
        };
        let mut f = node_finding(
            index,
            id,
            path.to_path_buf(),
            Category::LargeOld,
            SafetyLabel::AppData,
            rule_id,
        );
        f.explain = explain.to_string();
        f.subtitle = subtitle.map(str::to_string);
        out.push(f);
        hits.push(id);
        false
    });
    claimed.extend(hits);
    out
}

const LARGE_FILE: &str = "A large file of yours. Discky cannot tell whether you still need it; it moves to the Trash if removed.";
const OLD_DIR: &str = "Nothing in this folder has changed for a long time. Discky cannot tell whether you still need it; it moves to the Trash if removed.";
const DOWNLOADS: &str = "Something you downloaded. It can usually be downloaded again; it moves to the Trash if removed.";

/// Every proper ancestor of a claimed node.
fn ancestors_of(index: &Index, claimed: &HashSet<NodeId>) -> HashSet<NodeId> {
    let mut out = HashSet::new();
    for &id in claimed {
        let mut cur = index.node(id).parent;
        while let Some(p) = cur {
            if !out.insert(p) {
                break;
            }
            cur = index.node(p).parent;
        }
    }
    out
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
