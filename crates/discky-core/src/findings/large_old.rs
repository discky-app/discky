//! Pass 3: large files, directories untouched for a long time, and `~/Downloads`.

use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Thresholds;
use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Category, SafetyLabel};

use super::{Finding, Removal, node_finding, walk_unclaimed};

const DAY: i64 = 24 * 3600;

/// `LargeOld` findings for what earlier passes left unclaimed, inside `home` (roots not
/// at or under `home` are not walked; without a home there are none) and outside
/// `~/Library`:
///
/// - files whose `logical` **or** `allocated` size exceeds `large_file_bytes`. Logical
///   counts too: a sparse file that claims far more than it occupies is worth showing,
///   and its `"sparse"` flag and honest `allocated`/`freed_if_deleted` tell the user
///   that deleting it frees little;
/// - the topmost directories whose newest mtime is older than `old_days`;
/// - every direct child of `~/Downloads`, subtitled "Downloads".
///
/// `.git`, `.hg` and `.svn` directories are opaque: never entered (trashing a pack file
/// or an object dir corrupts the repository). One whose `agg_logical` or
/// `agg_allocated` exceeds `large_file_bytes` is reported whole as `vcs-history` with
/// `Removal::None`; smaller ones are skipped.
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
    let Some(home) = home else {
        return Vec::new();
    };
    let cutoff = now() - i64::from(thresholds.old_days) * DAY;
    let library = home.join("Library");
    let downloads = home.join("Downloads");
    let large = thresholds.large_file_bytes;
    let contains_claimed = ancestors_of(index, claimed);

    let mut out = Vec::new();
    let mut hits = Vec::new();
    walk_unclaimed(index, claimed, |id, path| {
        let node = index.node(id);
        let is_root = node.parent.is_none();
        if path.starts_with(&library) || (is_root && !path.starts_with(home)) {
            return false;
        }
        let is_dir = node.kind == ObjKind::Dir;
        if is_dir && let Some(title) = vcs_title(index.name(id).as_encoded_bytes()) {
            if !is_root && (node.agg_logical > large || node.agg_allocated > large) {
                let mut f = node_finding(
                    index,
                    id,
                    path.to_path_buf(),
                    Category::LargeOld,
                    SafetyLabel::AppData,
                    "vcs-history",
                );
                f.title = title.to_string();
                f.subtitle = path
                    .parent()
                    .and_then(Path::file_name)
                    .map(|n| n.to_string_lossy().into_owned());
                f.explain = VCS.to_string();
                f.removal = Removal::None;
                out.push(f);
                hits.push(id);
            }
            return false;
        }
        if is_root || path == home || path == downloads || contains_claimed.contains(&id) {
            return is_dir;
        }
        let (rule_id, explain, subtitle) = if path.parent() == Some(downloads.as_path()) {
            ("downloads", DOWNLOADS, Some("Downloads"))
        } else if is_dir && node.max_mtime < cutoff {
            ("old-dir", OLD_DIR, None)
        } else if node.kind == ObjKind::File && (node.logical > large || node.allocated > large) {
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

const VCS: &str =
    "Version-control history. Not removable here; run `git gc` or re-clone to shrink it.";

fn vcs_title(name: &[u8]) -> Option<&'static str> {
    match name {
        b".git" => Some("Git history"),
        b".hg" => Some("Mercurial history"),
        b".svn" => Some("Subversion history"),
        _ => None,
    }
}

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
