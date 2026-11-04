//! Read-only views over a [`Snapshot`]: disk overview, directory tree and search.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use globset::GlobBuilder;
use serde::{Deserialize, Serialize};

use crate::findings::apps::{RULE_APP, UNUSED_DAYS};
use crate::findings::{ComponentKind, Finding, FindingId, Removal};
use crate::fs::attr::ObjKind;
use crate::index::snapshot::{Actor, Snapshot};
use crate::index::{Index, NodeFlags, NodeId};
use crate::rules::{Category, SafetyLabel};

const SECS_PER_DAY: i64 = 86_400;

/// Every category, in sidebar order.
const CATEGORIES: [Category; 7] = [
    Category::Apps,
    Category::AppCaches,
    Category::Models,
    Category::DevCaches,
    Category::ProjectBuilds,
    Category::LanguageVersions,
    Category::LargeOld,
];

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("{0} is not in the snapshot")]
    NotInSnapshot(PathBuf),
}

#[derive(Clone, Debug, Serialize)]
pub struct VolumeInfo {
    pub mount: PathBuf,
    pub total: u64,
    pub used: u64,
    pub available: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Overview {
    pub volume: VolumeInfo,
    pub snapshot_at: Option<i64>,
    pub actor: Option<Actor>,
    pub scanned_allocated: u64,
    /// `allocated` bytes per category, over every finding not labelled `DoNotTouch`.
    pub by_category: Vec<(Category, u64)>,
    /// Sum of `allocated` over findings labelled `DoNotTouch` (counted in no category).
    pub protected_bytes: u64,
    /// Sum of `freed_if_deleted` over findings labelled `Regenerates`, except those
    /// removed by a command with a `freed_note` (it frees an unknown part of them).
    pub safe_to_free: u64,
    pub no_access: usize,
    /// Installed apps not opened for [`UNUSED_DAYS`] days (unknown last use counts), see
    /// [`is_unused_app`]; the sidebar shows this count for Applications.
    pub apps_unused: usize,
    /// How the last scan measured `freed_if_deleted`: `Some(false)` = fast mode
    /// (clone-aware only; blocks also held by APFS local snapshots are counted as freed),
    /// `Some(true)` = exact mode (the kernel's private size, enabled when Time Machine
    /// local snapshots exist). `None` only without a snapshot; recorded in
    /// [`SnapshotMeta::exact_private_size`](crate::index::snapshot::SnapshotMeta), so it is
    /// known for a snapshot loaded from disk too.
    pub exact_private_size: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TreeEntry {
    pub name: String,
    pub path: PathBuf,
    pub kind: ObjKind,
    pub allocated: u64,
    pub logical: u64,
    pub freed_if_deleted: u64,
    pub files: u32,
    pub modified: i64,
    pub flags: Vec<String>,
    pub finding: Option<FindingId>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SearchQuery {
    pub name_glob: Option<String>,
    pub min_allocated: Option<u64>,
    /// Entries with an unknown (zero) modification time never match.
    pub older_than_days: Option<u32>,
    pub kind: Option<ObjKind>,
    pub under: Option<PathBuf>,
    pub limit: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        SearchQuery {
            name_glob: None,
            min_allocated: None,
            older_than_days: None,
            kind: None,
            under: None,
            limit: 50,
        }
    }
}

/// Mount point and byte counts of the data volume (`/` if it is not available).
fn volume_info() -> VolumeInfo {
    ["/System/Volumes/Data", "/"]
        .iter()
        .find_map(|m| statfs(Path::new(m)))
        .unwrap_or_else(|| VolumeInfo {
            mount: PathBuf::from("/"),
            total: 0,
            used: 0,
            available: 0,
        })
}

fn statfs(mount: &Path) -> Option<VolumeInfo> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(mount.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated string and `st` is a writable buffer of
    // the size `statfs` expects; the struct is only read after the call reports success.
    let st = unsafe {
        if libc::statfs(c_path.as_ptr(), st.as_mut_ptr()) != 0 {
            return None;
        }
        st.assume_init()
    };
    let bsize = u64::from(st.f_bsize);
    let total = st.f_blocks * bsize;
    Some(VolumeInfo {
        mount: mount.to_path_buf(),
        total,
        used: total.saturating_sub(st.f_bfree * bsize),
        available: st.f_bavail * bsize,
    })
}

/// A finding's bytes in [`Overview::by_category`]: an app (a finding with an `AppBundle`
/// component) counts its bundle only — its leftovers are not claimed and may be other
/// findings too; anything else (leftover groups, receipts, other categories) its
/// `allocated`.
fn category_weight(f: &Finding) -> u64 {
    if f.category != Category::Apps {
        return f.allocated;
    }
    f.components
        .iter()
        .find(|c| c.kind == ComponentKind::AppBundle)
        .map_or(f.allocated, |c| c.allocated)
}

pub fn disk_overview(snap: Option<&Snapshot>) -> Overview {
    let volume = volume_info();
    let Some(snap) = snap else {
        return Overview {
            volume,
            snapshot_at: None,
            actor: None,
            scanned_allocated: 0,
            by_category: CATEGORIES.iter().map(|&c| (c, 0)).collect(),
            protected_bytes: 0,
            safe_to_free: 0,
            no_access: 0,
            apps_unused: 0,
            exact_private_size: None,
        };
    };
    let by_category = CATEGORIES
        .iter()
        .map(|&c| {
            let sum = snap
                .findings
                .iter()
                .filter(|f| f.category == c && f.label != SafetyLabel::DoNotTouch)
                .map(category_weight)
                .sum();
            (c, sum)
        })
        .collect();
    Overview {
        volume,
        snapshot_at: Some(snap.meta.created_at),
        actor: Some(snap.meta.actor),
        scanned_allocated: snap.index.total_allocated(),
        by_category,
        protected_bytes: snap
            .findings
            .iter()
            .filter(|f| f.label == SafetyLabel::DoNotTouch)
            .map(|f| f.allocated)
            .sum(),
        safe_to_free: snap
            .findings
            .iter()
            .filter(|f| f.label == SafetyLabel::Regenerates && !partial_command(f))
            .map(|f| f.freed_if_deleted)
            .sum(),
        no_access: snap.meta.no_access.len(),
        apps_unused: apps_unused(&snap.findings, now_secs()),
        exact_private_size: Some(snap.meta.exact_private_size),
    }
}

/// Whether `f` is an installed app (`rule_id` [`RULE_APP`]) not opened for at least
/// [`UNUSED_DAYS`] days at `now` (Unix seconds). An unknown last use counts as not opened.
pub fn is_unused_app(f: &Finding, now: i64) -> bool {
    f.rule_id == RULE_APP
        && f.modified
            .is_none_or(|t| now.saturating_sub(t) >= i64::from(UNUSED_DAYS) * SECS_PER_DAY)
}

/// How many of `findings` are unused apps, see [`is_unused_app`].
pub fn apps_unused(findings: &[Finding], now: i64) -> usize {
    findings.iter().filter(|f| is_unused_app(f, now)).count()
}

/// Removed by a command that frees only part of the finding (it carries a `freed_note`).
fn partial_command(f: &Finding) -> bool {
    matches!(
        &f.removal,
        Removal::Command {
            freed_note: Some(_),
            ..
        }
    )
}

fn finding_ids(snap: &Snapshot) -> HashMap<NodeId, FindingId> {
    snap.findings
        .iter()
        .filter_map(|f| Some((f.node?, f.id.clone())))
        .collect()
}

/// Node → owning finding (index into `Snapshot::findings`), for colouring and linking
/// disk-map tiles.
#[derive(Debug, Clone, Default)]
pub struct NodeFindings {
    by_node: HashMap<NodeId, usize>,
}

impl NodeFindings {
    /// Every finding with `node` → that node; every component with a `path` (leftover
    /// groups, app leftovers, receipts) → `index.find(path)` when it resolves. Earlier
    /// findings win on a collision.
    pub fn build(snap: &Snapshot) -> NodeFindings {
        let mut by_node = HashMap::new();
        for (i, f) in snap.findings.iter().enumerate() {
            if let Some(n) = f.node {
                by_node.entry(n).or_insert(i);
            }
            for p in f.components.iter().filter_map(|c| c.path.as_deref()) {
                if let Some(n) = snap.index.find(p) {
                    by_node.entry(n).or_insert(i);
                }
            }
        }
        NodeFindings { by_node }
    }

    /// The finding owning `id`: its own entry, else the nearest ancestor's.
    pub fn owner(&self, index: &Index, id: NodeId) -> Option<usize> {
        let mut cur = Some(id);
        while let Some(n) = cur {
            if let Some(&i) = self.by_node.get(&n) {
                return Some(i);
            }
            cur = index.node(n).parent;
        }
        None
    }

    /// Every entry: a node and the index (in `snap.findings`) of the finding it maps to,
    /// in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = (NodeId, usize)> + '_ {
        self.by_node.iter().map(|(&n, &i)| (n, i))
    }

    /// Direct entry only (the tile *is* the finding's node).
    pub fn direct(&self, id: NodeId) -> Option<usize> {
        self.by_node.get(&id).copied()
    }

    pub fn len(&self) -> usize {
        self.by_node.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_node.is_empty()
    }
}

fn flag_names(flags: NodeFlags) -> Vec<String> {
    [
        (NodeFlags::SPARSE, "sparse"),
        (NodeFlags::DATALESS, "dataless"),
        (NodeFlags::HARDLINK_DUP, "hardlinks"),
        (NodeFlags::NO_ACCESS, "no_access"),
        (NodeFlags::CLONE_SHARED, "clone_shared"),
    ]
    .into_iter()
    .filter(|&(flag, _)| flags.contains(flag))
    .map(|(_, name)| name.to_owned())
    .collect()
}

fn tree_entry(index: &Index, id: NodeId, findings: &HashMap<NodeId, FindingId>) -> TreeEntry {
    let n = index.node(id);
    let is_dir = n.kind == ObjKind::Dir;
    TreeEntry {
        name: index.name(id).to_string_lossy().into_owned(),
        path: index.path(id),
        kind: n.kind,
        allocated: n.agg_allocated,
        logical: n.agg_logical,
        freed_if_deleted: if is_dir { n.agg_private } else { n.private },
        files: n.agg_files,
        modified: if is_dir { n.max_mtime } else { n.mtime },
        flags: flag_names(n.flags),
        finding: findings.get(&id).cloned(),
    }
}

/// Direct children of `path`, largest first (ties by name), at most `limit`.
pub fn tree(snap: &Snapshot, path: &Path, limit: usize) -> Result<Vec<TreeEntry>, QueryError> {
    let index = &snap.index;
    let id = index
        .find(path)
        .ok_or_else(|| QueryError::NotInSnapshot(path.to_path_buf()))?;
    let findings = finding_ids(snap);
    let mut entries: Vec<TreeEntry> = index
        .children(id)
        .map(|c| tree_entry(index, c, &findings))
        .collect();
    entries.sort_by(|a, b| {
        b.allocated
            .cmp(&a.allocated)
            .then_with(|| a.name.cmp(&b.name))
    });
    entries.truncate(limit);
    Ok(entries)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// True if `id` is `ancestor` or lies below it.
fn is_within(index: &Index, mut id: NodeId, ancestor: NodeId) -> bool {
    loop {
        if id == ancestor {
            return true;
        }
        match index.node(id).parent {
            Some(p) => id = p,
            None => return false,
        }
    }
}

/// Linear scan over all nodes, returning the `limit` largest matches, largest first (ties
/// by path). Ties at the cut boundary are broken by `NodeId`, not path. Empty if `name_glob` is invalid or `under` is unknown.
pub fn search(snap: &Snapshot, q: &SearchQuery) -> Vec<TreeEntry> {
    let index = &snap.index;
    let matcher = match &q.name_glob {
        Some(g) => match GlobBuilder::new(g).literal_separator(false).build() {
            Ok(glob) => Some(glob.compile_matcher()),
            Err(_) => return Vec::new(),
        },
        None => None,
    };
    let under = match &q.under {
        Some(p) => match index.find(p) {
            Some(id) => Some(id),
            None => return Vec::new(),
        },
        None => None,
    };
    let cutoff = q
        .older_than_days
        .map(|d| now_secs() - i64::from(d) * SECS_PER_DAY);

    let mut hits: Vec<(u64, u32)> = (0..index.nodes.len() as u32)
        .filter(|&i| {
            let id = NodeId(i);
            let n = index.node(id);
            let modified = if n.kind == ObjKind::Dir {
                n.max_mtime
            } else {
                n.mtime
            };
            q.kind.is_none_or(|k| n.kind == k)
                && q.min_allocated.is_none_or(|m| n.agg_allocated >= m)
                && cutoff.is_none_or(|c| modified > 0 && modified < c)
                && matcher.as_ref().is_none_or(|m| m.is_match(index.name(id)))
                && under.is_none_or(|u| is_within(index, id, u))
        })
        .map(|i| (index.node(NodeId(i)).agg_allocated, i))
        .collect();
    // Keep the top `limit` by allocated desc (ties by node id) before building any entry.
    let by_rank = |a: &(u64, u32), b: &(u64, u32)| b.0.cmp(&a.0).then(a.1.cmp(&b.1));
    if q.limit == 0 {
        return Vec::new();
    }
    if hits.len() > q.limit {
        hits.select_nth_unstable_by(q.limit - 1, by_rank);
        hits.truncate(q.limit);
    }
    let findings = finding_ids(snap);
    let mut entries: Vec<TreeEntry> = hits
        .into_iter()
        .map(|(_, i)| tree_entry(index, NodeId(i), &findings))
        .collect();
    entries.sort_by(|a, b| {
        b.allocated
            .cmp(&a.allocated)
            .then_with(|| a.path.cmp(&b.path))
    });
    entries
}

/// Findings passing every filter, paged; also returns the count before paging.
pub fn findings_in(
    snap: &Snapshot,
    category: Option<Category>,
    label: Option<SafetyLabel>,
    min_allocated: u64,
    older_than_days: Option<u32>,
    offset: usize,
    limit: usize,
) -> (Vec<&Finding>, usize) {
    let cutoff = older_than_days.map(|d| now_secs() - i64::from(d) * SECS_PER_DAY);
    let matching: Vec<&Finding> = snap
        .findings
        .iter()
        .filter(|f| category.is_none_or(|c| f.category == c))
        .filter(|f| label.is_none_or(|l| f.label == l))
        .filter(|f| f.allocated >= min_allocated)
        .filter(|f| cutoff.is_none_or(|c| f.modified.is_some_and(|m| m > 0 && m < c)))
        .collect();
    let total = matching.len();
    (
        matching.into_iter().skip(offset).take(limit).collect(),
        total,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::apps::RULE_LEFTOVERS;

    fn app(rule: &str, modified: Option<i64>) -> Finding {
        Finding {
            id: FindingId(format!("{rule}-{modified:?}")),
            category: Category::Apps,
            title: "App".into(),
            subtitle: None,
            path: None,
            node: None,
            allocated: 1,
            logical: 1,
            freed_if_deleted: 1,
            modified,
            label: SafetyLabel::AppData,
            rule_id: rule.into(),
            explain: String::new(),
            removal: Removal::None,
            flags: vec![],
            components: vec![],
        }
    }

    #[test]
    fn apps_unused_counts_unknown_and_old() {
        let now = 1_000 * SECS_PER_DAY;
        let limit = i64::from(UNUSED_DAYS) * SECS_PER_DAY;
        let findings = [
            app(RULE_APP, None),
            app(RULE_APP, Some(now - limit)),
            app(RULE_APP, Some(now - limit + 1)),
            app(RULE_APP, Some(now)),
            app(RULE_LEFTOVERS, None),
            app("pkg-receipts", None),
        ];
        assert_eq!(apps_unused(&findings, now), 2);
        assert!(is_unused_app(&findings[0], now));
        assert!(is_unused_app(&findings[1], now));
        assert!(!is_unused_app(&findings[2], now));
        assert!(!is_unused_app(&findings[4], now));
    }
}
