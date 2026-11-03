//! Disk-map state: the folder shown, depth, colour and weight modes, exclusions, and the
//! nested tile layout with hit-testing. Pure: no GPUI (colours live in `crate::palette`).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use discky_core::findings::Finding;
use discky_core::fs::attr::ObjKind;
use discky_core::index::snapshot::Snapshot;
use discky_core::index::{Node, NodeFlags, NodeId};
use discky_core::query::NodeFindings;
use discky_core::rules::Category;

pub use super::layout::Rect;
use super::layout::{Item, Slot, squarify};
use crate::format;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Category,
    Age,
    Files,
}

impl ColorMode {
    pub fn label(self) -> &'static str {
        match self {
            ColorMode::Category => "Category",
            ColorMode::Age => "Age",
            ColorMode::Files => "Files",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightMode {
    OnDisk,
    Claimed,
}

impl WeightMode {
    pub fn label(self) -> &'static str {
        match self {
            WeightMode::OnDisk => "On disk",
            WeightMode::Claimed => "Claimed",
        }
    }
}

pub const DEPTH_MIN: u8 = 1;
pub const DEPTH_MAX: u8 = 4;
pub const DEFAULT_DEPTH: u8 = 3;
pub const PAD: f32 = 2.0;
pub const HEADER_H: f32 = 16.0;
pub const LABEL_MIN_W: f32 = 40.0;
pub const LABEL_MIN_H: f32 = 14.0;
pub const MAX_TILES: usize = 6000;
/// Upper bounds (exclusive, in days) of age buckets 0..=3; 4 = older, 5 = unknown.
pub const AGE_DAYS: [i64; 4] = [30, 180, 365, 730];
/// Upper bounds (inclusive) of file-count buckets 0..=4; 5 = more.
pub const FILE_BUCKETS: [u32; 5] = [1, 10, 100, 1_000, 10_000];
pub const CAPTION_SPARSE: &str = "sparse";
pub const CAPTION_CLOUD: &str = "in the cloud";
pub const CAPTION_NO_ACCESS: &str = "no access";
pub const TOP_LABEL: &str = "Disk";

const SECS_PER_DAY: i64 = 86_400;

/// Every category, in sidebar order, with its display name.
const CATEGORIES: [(Category, &str); 7] = [
    (Category::Apps, "Applications"),
    (Category::AppCaches, "App caches"),
    (Category::Models, "Models"),
    (Category::DevCaches, "Dev caches"),
    (Category::ProjectBuilds, "Project builds"),
    (Category::LanguageVersions, "Language versions"),
    (Category::LargeOld, "Large & old"),
];

/// User-facing flag names for the tooltip, in display order.
const FLAG_NAMES: [(NodeFlags, &str); 5] = [
    (NodeFlags::SPARSE, "sparse"),
    (NodeFlags::DATALESS, "in the cloud"),
    (NodeFlags::HARDLINK_DUP, "hard link"),
    (NodeFlags::NO_ACCESS, "no access"),
    (NodeFlags::CLONE_SHARED, "clone"),
];

/// How a tile is filled; `crate::palette` turns it into a colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paint {
    Category(Option<Category>),
    Cloud,
    NoAccess,
    Age(u8),
    Files(u8),
    Rest,
}

#[derive(Debug, Clone)]
pub struct Tile {
    /// `None` for a Rest tile.
    pub node: Option<NodeId>,
    pub rect: Rect,
    /// 0 = a child of the current folder.
    pub depth: u8,
    pub label: String,
    pub caption: Option<&'static str>,
    pub paint: Paint,
    pub sparse: bool,
    /// Dataless (contents in the cloud).
    pub dashed: bool,
    /// `(count, weight)` of the items merged into a Rest tile.
    pub rest: Option<(usize, u64)>,
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crumb {
    pub label: String,
    /// `None` for the top (all scan roots).
    pub node: Option<NodeId>,
}

/// What exclusions below a node removed from its aggregates.
#[derive(Debug, Clone, Copy, Default)]
struct Subtracted {
    on_disk: u64,
    claimed: u64,
    files: u32,
}

pub struct MapModel {
    snap: Arc<Snapshot>,
    findings: NodeFindings,
    home: PathBuf,
    now: i64,
    root: Option<NodeId>,
    depth: u8,
    color: ColorMode,
    weight: WeightMode,
    excluded: HashSet<NodeId>,
    subtracted: HashMap<NodeId, Subtracted>,
}

impl MapModel {
    /// Depth [`DEFAULT_DEPTH`], colour by category, weight on disk, at the top (scan roots).
    pub fn new(snap: Arc<Snapshot>, home: PathBuf, now: i64) -> Self {
        MapModel {
            findings: NodeFindings::build(&snap),
            snap,
            home,
            now,
            root: None,
            depth: DEFAULT_DEPTH,
            color: ColorMode::Category,
            weight: WeightMode::OnDisk,
            excluded: HashSet::new(),
            subtracted: HashMap::new(),
        }
    }

    pub fn snapshot(&self) -> &Arc<Snapshot> {
        &self.snap
    }

    /// Keeps the current folder when its path exists in the new index, else returns to the top; clears exclusions.
    pub fn set_snapshot(&mut self, snap: Arc<Snapshot>) {
        let path = self.root.map(|r| self.snap.index.path(r));
        self.root = path
            .and_then(|p| snap.index.find(&p))
            .filter(|&n| snap.index.node(n).kind == ObjKind::Dir);
        self.findings = NodeFindings::build(&snap);
        self.snap = snap;
        self.excluded.clear();
        self.subtracted.clear();
    }

    pub fn root(&self) -> Option<NodeId> {
        self.root
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn color(&self) -> ColorMode {
        self.color
    }

    pub fn weight_mode(&self) -> WeightMode {
        self.weight
    }

    /// Clamped to `DEPTH_MIN..=DEPTH_MAX`; true when the depth changed.
    pub fn set_depth(&mut self, d: u8) -> bool {
        let d = d.clamp(DEPTH_MIN, DEPTH_MAX);
        let changed = d != self.depth;
        self.depth = d;
        changed
    }

    pub fn set_color(&mut self, c: ColorMode) -> bool {
        let changed = c != self.color;
        self.color = c;
        changed
    }

    pub fn set_weight_mode(&mut self, w: WeightMode) -> bool {
        let changed = w != self.weight;
        self.weight = w;
        changed
    }

    /// Makes `node` the current folder: only a directory with a child of weight > 0.
    pub fn enter(&mut self, node: NodeId) -> bool {
        let idx = &self.snap.index;
        if idx.node(node).kind != ObjKind::Dir || self.weight(node) == 0 {
            return false;
        }
        if !idx.children(node).any(|c| self.weight(c) > 0) {
            return false;
        }
        self.root = Some(node);
        true
    }

    /// To the current folder's parent, or the top from a scan root; false at the top.
    pub fn up(&mut self) -> bool {
        match self.root {
            Some(r) => {
                self.root = self.snap.index.node(r).parent;
                true
            }
            None => false,
        }
    }

    pub fn go_to(&mut self, node: Option<NodeId>) {
        self.root = node;
    }

    /// [`TOP_LABEL`], then the scan root ("~" for home, else its full path), then each folder down to the current one.
    pub fn crumbs(&self) -> Vec<Crumb> {
        let idx = &self.snap.index;
        let mut chain = Vec::new();
        let mut cur = self.root;
        while let Some(n) = cur {
            chain.push(n);
            cur = idx.node(n).parent;
        }
        let mut out = vec![Crumb {
            label: TOP_LABEL.to_string(),
            node: None,
        }];
        for n in chain.into_iter().rev() {
            let label = match idx.roots.iter().position(|&r| r == n) {
                Some(i) if idx.root_paths[i] == self.home => "~".to_string(),
                Some(i) => idx.root_paths[i].to_string_lossy().into_owned(),
                None => idx.name(n).to_string_lossy().into_owned(),
            };
            out.push(Crumb {
                label,
                node: Some(n),
            });
        }
        out
    }

    /// `(weight, files)` of the current folder after exclusions; at the top, over all scan roots.
    pub fn totals(&self) -> (u64, u32) {
        let nodes: Vec<NodeId> = match self.root {
            Some(r) => vec![r],
            None => self.snap.index.roots.clone(),
        };
        nodes.iter().fold((0, 0), |(w, f), &n| {
            (w + self.weight(n), f.saturating_add(self.files(n)))
        })
    }

    /// Hides each path that resolves in the index and takes its weight (both modes) and
    /// file count off every ancestor. Paths already hidden, or inside a hidden folder, are skipped.
    pub fn exclude(&mut self, paths: &[PathBuf]) {
        for p in paths {
            let Some(node) = self.snap.index.find(p) else {
                continue;
            };
            if self.is_hidden(node) {
                continue;
            }
            let delta = Subtracted {
                on_disk: self.weight_in(node, WeightMode::OnDisk),
                claimed: self.weight_in(node, WeightMode::Claimed),
                files: self.files(node),
            };
            self.excluded.insert(node);
            let mut cur = self.snap.index.node(node).parent;
            while let Some(a) = cur {
                let s = self.subtracted.entry(a).or_default();
                s.on_disk += delta.on_disk;
                s.claimed += delta.claimed;
                s.files += delta.files;
                cur = self.snap.index.node(a).parent;
            }
        }
    }

    /// The tile weight under the current mode; see [`MapModel::weight_in`].
    pub fn weight(&self, node: NodeId) -> u64 {
        self.weight_in(node, self.weight)
    }

    /// 0 when excluded or a hard-link duplicate; a dataless file is 0 on disk and its
    /// logical size when claimed; otherwise a directory's aggregate or a file's own size,
    /// minus what exclusions below it removed.
    fn weight_in(&self, node: NodeId, mode: WeightMode) -> u64 {
        if self.excluded.contains(&node) {
            return 0;
        }
        let n = self.snap.index.node(node);
        if n.flags.contains(NodeFlags::HARDLINK_DUP) {
            return 0;
        }
        let dir = n.kind == ObjKind::Dir;
        let raw = match mode {
            WeightMode::OnDisk if n.flags.contains(NodeFlags::DATALESS) => 0,
            WeightMode::OnDisk if dir => n.agg_allocated,
            WeightMode::OnDisk => n.allocated,
            WeightMode::Claimed if dir => n.agg_logical,
            WeightMode::Claimed => n.logical,
        };
        let sub = self.subtracted.get(&node).map_or(0, |s| match mode {
            WeightMode::OnDisk => s.on_disk,
            WeightMode::Claimed => s.claimed,
        });
        raw.saturating_sub(sub)
    }

    fn files(&self, node: NodeId) -> u32 {
        if self.excluded.contains(&node) {
            return 0;
        }
        let sub = self.subtracted.get(&node).map_or(0, |s| s.files);
        self.snap.index.node(node).agg_files.saturating_sub(sub)
    }

    /// Excluded itself or below an excluded folder.
    fn is_hidden(&self, node: NodeId) -> bool {
        let mut cur = Some(node);
        while let Some(n) = cur {
            if self.excluded.contains(&n) {
                return true;
            }
            cur = self.snap.index.node(n).parent;
        }
        false
    }

    /// Nested tiles of the current folder in `rect`, depth-first (a parent before its
    /// children). A directory's children go in its rect inset by [`PAD`] below a
    /// [`HEADER_H`] label strip, only when the tile is at least `2·HEADER_H` tall and
    /// [`LABEL_MIN_W`] wide. Stops at [`MapModel::depth`] levels and [`MAX_TILES`] tiles.
    pub fn layout(&self, rect: Rect) -> Vec<Tile> {
        let top: Vec<NodeId> = match self.root {
            Some(r) => self.snap.index.children(r).collect(),
            None => self.snap.index.roots.clone(),
        };
        let mut out = Vec::new();
        self.lay_out(&top, rect, 0, &mut out);
        out
    }

    fn lay_out(&self, nodes: &[NodeId], rect: Rect, depth: u8, out: &mut Vec<Tile>) {
        let items: Vec<Item<NodeId>> = nodes
            .iter()
            .map(|&key| Item {
                key,
                weight: self.weight(key),
            })
            .collect();
        for placed in squarify(&items, rect) {
            if out.len() >= MAX_TILES {
                return;
            }
            let r = placed.rect;
            match placed.slot {
                Slot::Rest { count, weight } => out.push(Tile {
                    node: None,
                    rect: r,
                    depth,
                    label: format!("{count} more"),
                    caption: None,
                    paint: Paint::Rest,
                    sparse: false,
                    dashed: false,
                    rest: Some((count, weight)),
                    is_dir: false,
                }),
                Slot::Item(node) => {
                    let tile = self.tile(node, r, depth);
                    let nest = tile.is_dir
                        && depth + 1 < self.depth
                        && r.h >= 2.0 * HEADER_H
                        && r.w >= LABEL_MIN_W;
                    out.push(tile);
                    if nest {
                        let inner = r.inset(PAD);
                        let body = Rect {
                            x: inner.x,
                            y: inner.y + HEADER_H,
                            w: inner.w,
                            h: (inner.h - HEADER_H).max(0.0),
                        };
                        let kids: Vec<NodeId> = self.snap.index.children(node).collect();
                        self.lay_out(&kids, body, depth + 1, out);
                    }
                }
            }
        }
    }

    fn tile(&self, node: NodeId, rect: Rect, depth: u8) -> Tile {
        let idx = &self.snap.index;
        let n = idx.node(node);
        let caption = if n.flags.contains(NodeFlags::NO_ACCESS) {
            Some(CAPTION_NO_ACCESS)
        } else if n.flags.contains(NodeFlags::DATALESS) {
            Some(CAPTION_CLOUD)
        } else if n.flags.contains(NodeFlags::SPARSE) {
            Some(CAPTION_SPARSE)
        } else {
            None
        };
        Tile {
            node: Some(node),
            rect,
            depth,
            label: idx.name(node).to_string_lossy().into_owned(),
            caption,
            paint: self.paint_of(node),
            sparse: n.flags.contains(NodeFlags::SPARSE),
            dashed: n.flags.contains(NodeFlags::DATALESS),
            rest: None,
            is_dir: n.kind == ObjKind::Dir,
        }
    }

    /// Index of the deepest tile containing `(x, y)` (the last match, since parents come first).
    pub fn tile_at(tiles: &[Tile], x: f32, y: f32) -> Option<usize> {
        tiles.iter().rposition(|t| t.rect.contains(x, y))
    }

    /// Cloud for dataless, NoAccess for unreadable, else by the colour mode.
    pub fn paint_of(&self, node: NodeId) -> Paint {
        let n = self.snap.index.node(node);
        if n.flags.contains(NodeFlags::DATALESS) {
            return Paint::Cloud;
        }
        if n.flags.contains(NodeFlags::NO_ACCESS) {
            return Paint::NoAccess;
        }
        match self.color {
            ColorMode::Category => Paint::Category(self.finding_of(node).map(|f| f.category)),
            ColorMode::Age => Paint::Age(age_bucket(modified(n), self.now)),
            ColorMode::Files => Paint::Files(files_bucket(self.files(node))),
        }
    }

    /// The finding owning `node`: its own, else the nearest ancestor's.
    pub fn finding_index(&self, node: NodeId) -> Option<usize> {
        self.findings.owner(&self.snap.index, node)
    }

    /// The finding whose node `node` is.
    pub fn direct_finding_index(&self, node: NodeId) -> Option<usize> {
        self.findings.direct(node)
    }

    pub fn finding_of(&self, node: NodeId) -> Option<&Finding> {
        self.finding_index(node).map(|i| &self.snap.findings[i])
    }

    /// Title and the rows that apply: "On disk", "Claimed" (when it differs), "Files"
    /// (folders), "Modified", "Category", "Flags". A Rest tile shows its combined weight.
    pub fn tooltip(&self, tile: &Tile) -> (String, Vec<(&'static str, String)>) {
        let Some(node) = tile.node else {
            let (count, weight) = tile.rest.unwrap_or((0, 0));
            return (
                format!("{count} more"),
                vec![(self.weight.label(), format::bytes(weight))],
            );
        };
        let idx = &self.snap.index;
        let n = idx.node(node);
        let on_disk = self.weight_in(node, WeightMode::OnDisk);
        let claimed = self.weight_in(node, WeightMode::Claimed);
        let mut rows = vec![("On disk", format::bytes(on_disk))];
        if claimed != on_disk {
            rows.push(("Claimed", format::bytes(claimed)));
        }
        if n.kind == ObjKind::Dir {
            rows.push(("Files", format::count(u64::from(self.files(node)))));
        }
        let m = modified(n);
        if m > 0 {
            rows.push(("Modified", format::when(m)));
        }
        if let Some(f) = self.finding_of(node) {
            rows.push(("Category", format!("{} · {}", f.category, f.title)));
        }
        let flags: Vec<&str> = FLAG_NAMES
            .iter()
            .filter(|(f, _)| n.flags.contains(*f))
            .map(|&(_, name)| name)
            .collect();
        if !flags.is_empty() {
            rows.push(("Flags", flags.join(", ")));
        }
        (idx.name(node).to_string_lossy().into_owned(), rows)
    }

    /// Swatches for the current colour mode.
    pub fn legend(&self) -> Vec<(Paint, &'static str)> {
        match self.color {
            ColorMode::Category => CATEGORIES
                .iter()
                .map(|&(c, name)| (Paint::Category(Some(c)), name))
                .chain([
                    (Paint::Category(None), "Not categorized"),
                    (Paint::Cloud, "In the cloud"),
                ])
                .collect(),
            ColorMode::Age => [
                "< 1 month",
                "< 6 months",
                "< 1 year",
                "< 2 years",
                "older",
                "unknown",
            ]
            .into_iter()
            .zip(0u8..)
            .map(|(name, b)| (Paint::Age(b), name))
            .collect(),
            ColorMode::Files => ["1", "≤ 10", "≤ 100", "≤ 1 000", "≤ 10 000", "more"]
                .into_iter()
                .zip(0u8..)
                .map(|(name, b)| (Paint::Files(b), name))
                .collect(),
        }
    }
}

/// A file's mtime, a directory's newest mtime inside it.
fn modified(n: &Node) -> i64 {
    if n.kind == ObjKind::Dir {
        n.max_mtime
    } else {
        n.mtime
    }
}

/// 0..=3: younger than `AGE_DAYS[i]` days; 4: older; 5: unknown (`modified <= 0`).
/// Times in the future count as new.
pub fn age_bucket(modified: i64, now: i64) -> u8 {
    if modified <= 0 {
        return 5;
    }
    let days = now.saturating_sub(modified).max(0) / SECS_PER_DAY;
    AGE_DAYS.iter().position(|&d| days < d).unwrap_or(4) as u8
}

/// 0..=4: at most `FILE_BUCKETS[i]` files; 5: more.
pub fn files_bucket(files: u32) -> u8 {
    FILE_BUCKETS
        .iter()
        .position(|&b| files <= b)
        .unwrap_or(FILE_BUCKETS.len()) as u8
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use discky_core::findings::{Finding, FindingId, Removal};
    use discky_core::fs::walk::{ScanOptions, walk};
    use discky_core::index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotMeta};
    use discky_core::index::{Index, NodeFlags, NodeId};
    use discky_core::rules::{Category, SafetyLabel};

    use super::{
        CAPTION_CLOUD, Crumb, HEADER_H, MAX_TILES, MapModel, PAD, Paint, Rect, TOP_LABEL, Tile,
        WeightMode, age_bucket, files_bucket,
    };

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn touch(p: &Path, bytes: usize) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, vec![b'x'; bytes]).unwrap();
    }

    fn scan(roots: &[&Path]) -> Index {
        walk(
            &ScanOptions {
                roots: roots.iter().map(|r| r.to_path_buf()).collect(),
                exclude: globset::GlobSet::empty(),
                threads: 0,
                exact_private_size: false,
                cancel: None,
            },
            &|_| {},
        )
    }

    fn wrap(index: Index, findings: Vec<Finding>) -> Arc<Snapshot> {
        Arc::new(Snapshot {
            meta: SnapshotMeta {
                format_version: SNAPSHOT_FORMAT,
                created_at: 0,
                actor: Actor::App,
                roots: index.root_paths.clone(),
                no_access: vec![],
                node_count: index.len() as u32,
                exact_private_size: false,
            },
            index: Arc::new(index),
            findings,
        })
    }

    /// Sets a file's own sizes and moves every ancestor's aggregates by the same delta.
    fn set_sizes(index: &mut Index, id: NodeId, allocated: u64, logical: u64) {
        let n = &index.nodes[id.0 as usize];
        let (da, dl) = (
            allocated as i128 - n.allocated as i128,
            logical as i128 - n.logical as i128,
        );
        let mut cur = Some(id);
        while let Some(c) = cur {
            let n = &mut index.nodes[c.0 as usize];
            if c == id {
                n.allocated = allocated;
                n.logical = logical;
            }
            n.agg_allocated = (n.agg_allocated as i128 + da) as u64;
            n.agg_logical = (n.agg_logical as i128 + dl) as u64;
            cur = n.parent;
        }
    }

    fn flag(index: &mut Index, id: NodeId, f: NodeFlags) {
        index.nodes[id.0 as usize].flags |= f;
    }

    fn finding(index: &Index, category: Category, path: &Path) -> Finding {
        Finding {
            id: FindingId::for_path(path),
            category,
            title: "Example".into(),
            subtitle: None,
            path: Some(path.into()),
            node: index.find(path),
            allocated: 1,
            logical: 1,
            freed_if_deleted: 1,
            modified: None,
            label: SafetyLabel::Regenerates,
            rule_id: "r".into(),
            explain: String::new(),
            removal: Removal::Trash {
                paths: vec![path.into()],
            },
            flags: vec![],
            components: vec![],
        }
    }

    fn rect(w: f32, h: f32) -> Rect {
        Rect {
            x: 0.0,
            y: 0.0,
            w,
            h,
        }
    }

    fn tile_of(tiles: &[Tile], id: NodeId) -> Option<&Tile> {
        tiles.iter().find(|t| t.node == Some(id))
    }

    /// `root/a/{one,two}`, `root/b/three`, `root/top`.
    fn tree(root: &Path) {
        touch(&root.join("a/one"), 5_000);
        touch(&root.join("a/two"), 9_000);
        touch(&root.join("b/three"), 20_000);
        touch(&root.join("top"), 1_000);
    }

    #[test]
    fn top_level_lays_out_scan_roots_and_crumbs_start_with_disk() {
        let d = tempfile::tempdir().unwrap();
        let (r1, r2) = (d.path().join("one"), d.path().join("two"));
        touch(&r1.join("f"), 4_000);
        touch(&r2.join("g"), 8_000);
        let mut m = MapModel::new(wrap(scan(&[&r1, &r2]), vec![]), d.path().into(), NOW);
        let tiles = m.layout(rect(400.0, 300.0));
        let top: Vec<_> = tiles.iter().filter(|t| t.depth == 0).collect();
        assert_eq!(top.len(), 2);
        let idx = m.snapshot().index.clone();
        for t in &top {
            assert!(idx.roots.contains(&t.node.unwrap()));
        }
        assert_eq!(
            m.crumbs(),
            vec![Crumb {
                label: TOP_LABEL.into(),
                node: None
            }]
        );
        assert_eq!(m.root(), None);
        let (total, files) = m.totals();
        let expect: u64 = idx.roots.iter().map(|&r| idx.node(r).agg_allocated).sum();
        assert_eq!((total, files), (expect, 2));
        // A root that is not home shows its full path.
        assert!(m.enter(idx.roots[0]));
        assert_eq!(m.crumbs()[1].label, r1.to_string_lossy());
    }

    #[test]
    fn enter_and_up_walk_the_tree_and_crumbs_follow() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let idx = m.snapshot().index.clone();
        let root = idx.roots[0];
        let a = idx.find(&d.path().join("a")).unwrap();
        let top = idx.find(&d.path().join("top")).unwrap();
        assert!(m.enter(root));
        assert!(m.enter(a));
        assert_eq!(m.root(), Some(a));
        assert_eq!(
            m.crumbs(),
            vec![
                Crumb {
                    label: TOP_LABEL.into(),
                    node: None
                },
                Crumb {
                    label: "~".into(),
                    node: Some(root)
                },
                Crumb {
                    label: "a".into(),
                    node: Some(a)
                },
            ]
        );
        assert!(!m.enter(top), "a file cannot be entered");
        assert!(m.up());
        assert_eq!(m.root(), Some(root));
        assert!(m.up());
        assert_eq!(m.root(), None);
        assert!(!m.up());
        m.go_to(Some(a));
        assert_eq!(m.root(), Some(a));
        m.go_to(None);
        assert_eq!(m.crumbs().len(), 1);
    }

    #[test]
    fn weights_follow_the_mode() {
        let d = tempfile::tempdir().unwrap();
        touch(&d.path().join("f"), 100);
        let mut idx = scan(&[d.path()]);
        let f = idx.find(&d.path().join("f")).unwrap();
        set_sizes(&mut idx, f, 4096, 1 << 20);
        let mut m = MapModel::new(wrap(idx, vec![]), d.path().into(), NOW);
        assert_eq!(m.weight(f), 4096);
        assert_eq!(m.totals().0, 4096);
        assert!(m.set_weight_mode(WeightMode::Claimed));
        assert!(!m.set_weight_mode(WeightMode::Claimed));
        assert_eq!(m.weight_mode(), WeightMode::Claimed);
        assert_eq!(m.weight(f), 1 << 20);
        assert_eq!(m.totals().0, 1 << 20);
    }

    #[test]
    fn dataless_hidden_on_disk_dashed_when_claimed() {
        let d = tempfile::tempdir().unwrap();
        touch(&d.path().join("local"), 10_000);
        touch(&d.path().join("cloud"), 10);
        let mut idx = scan(&[d.path()]);
        let cloud = idx.find(&d.path().join("cloud")).unwrap();
        let local = idx.find(&d.path().join("local")).unwrap();
        set_sizes(&mut idx, cloud, 0, 100);
        flag(&mut idx, cloud, NodeFlags::DATALESS);
        let local_alloc = idx.node(local).allocated;
        let local_logical = idx.node(local).logical;
        let mut m = MapModel::new(wrap(idx, vec![]), d.path().into(), NOW);
        let root = m.snapshot().index.roots[0];
        assert!(m.enter(root));
        let tiles = m.layout(rect(300.0, 200.0));
        assert!(tile_of(&tiles, cloud).is_none());
        assert!(tile_of(&tiles, local).is_some());
        assert_eq!(m.totals().0, local_alloc);

        m.set_weight_mode(WeightMode::Claimed);
        let tiles = m.layout(rect(300.0, 200.0));
        let t = tile_of(&tiles, cloud).expect("dataless tile under Claimed");
        assert!(t.dashed);
        assert_eq!(t.caption, Some(CAPTION_CLOUD));
        assert_eq!(t.paint, Paint::Cloud);
        assert_eq!(m.weight(cloud), 100);
        assert_eq!(m.totals().0, local_logical + 100);
    }

    #[test]
    fn hardlink_duplicates_weigh_zero() {
        let d = tempfile::tempdir().unwrap();
        touch(&d.path().join("orig"), 10_000);
        fs::hard_link(d.path().join("orig"), d.path().join("link")).unwrap();
        let mut idx = scan(&[d.path()]);
        let root = idx.roots[0];
        let dup = idx
            .children(root)
            .find(|&c| idx.node(c).flags.contains(NodeFlags::HARDLINK_DUP));
        // The walker flags the second name it sees; make sure one is flagged either way.
        let dup = dup.unwrap_or_else(|| {
            let l = idx.find(&d.path().join("link")).unwrap();
            let logical = idx.node(l).logical;
            set_sizes(&mut idx, l, 0, logical);
            flag(&mut idx, l, NodeFlags::HARDLINK_DUP);
            l
        });
        assert_eq!(idx.node(dup).allocated, 0);
        let mut m = MapModel::new(wrap(idx, vec![]), d.path().into(), NOW);
        assert!(m.enter(root));
        for mode in [WeightMode::OnDisk, WeightMode::Claimed] {
            m.set_weight_mode(mode);
            assert_eq!(m.weight(dup), 0);
            assert!(tile_of(&m.layout(rect(300.0, 200.0)), dup).is_none());
        }
    }

    #[test]
    fn nested_layout_respects_depth_and_header() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let root = m.snapshot().index.roots[0];
        assert!(m.enter(root));
        assert!(m.set_depth(1));
        let tiles = m.layout(rect(600.0, 400.0));
        assert_eq!(tiles.len(), 3);
        assert!(tiles.iter().all(|t| t.depth == 0));

        assert!(m.set_depth(2));
        assert!(!m.set_depth(2));
        assert_eq!(m.depth(), 2);
        let tiles = m.layout(rect(600.0, 400.0));
        assert!(tiles.iter().all(|t| t.depth <= 1));
        let a = m.snapshot().index.find(&d.path().join("a")).unwrap();
        let pos = tiles.iter().position(|t| t.node == Some(a)).unwrap();
        let parent = tiles[pos].rect;
        let inner = parent.inset(PAD);
        let kids: Vec<_> = tiles[pos + 1..]
            .iter()
            .take_while(|t| t.depth == 1)
            .collect();
        assert_eq!(kids.len(), 2);
        for k in kids {
            assert!(k.rect.x >= inner.x - 1e-3 && k.rect.x + k.rect.w <= inner.x + inner.w + 1e-3);
            assert!(k.rect.y >= inner.y + HEADER_H - 1e-3);
            assert!(k.rect.y + k.rect.h <= inner.y + inner.h + 1e-3);
        }
        // Too small for a header: no children.
        let tiles = m.layout(rect(30.0, 20.0));
        assert!(tiles.iter().all(|t| t.depth == 0));
    }

    #[test]
    fn layout_never_exceeds_max_tiles() {
        let d = tempfile::tempdir().unwrap();
        // 16 × (1 + 400 + Rest) would be 6 432 tiles: enough to hit the cap.
        for i in 0..16 {
            for j in 0..1_000 {
                touch(&d.path().join(format!("d{i:02}/f{j:04}")), 1);
            }
        }
        let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let root = m.snapshot().index.roots[0];
        assert!(m.enter(root));
        m.set_depth(4);
        let tiles = m.layout(rect(800.0, 600.0));
        assert!(tiles.len() <= MAX_TILES);
        assert_eq!(tiles.len(), MAX_TILES);
        let rest = tiles.iter().find(|t| t.rest.is_some()).expect("rest tile");
        assert_eq!(rest.paint, Paint::Rest);
        assert_eq!(rest.node, None);
        let (count, _) = rest.rest.unwrap();
        assert_eq!(rest.label, format!("{count} more"));
    }

    #[test]
    fn tile_at_returns_the_deepest_tile_and_none_outside() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let root = m.snapshot().index.roots[0];
        assert!(m.enter(root));
        m.set_depth(2);
        let tiles = m.layout(rect(600.0, 400.0));
        let child = tiles.iter().position(|t| t.depth == 1).unwrap();
        let r = tiles[child].rect;
        let hit = MapModel::tile_at(&tiles, r.x + r.w / 2.0, r.y + r.h / 2.0);
        assert_eq!(hit, Some(child));
        assert_eq!(MapModel::tile_at(&tiles, -5.0, 10.0), None);
        assert_eq!(MapModel::tile_at(&tiles, 601.0, 10.0), None);
    }

    #[test]
    fn tile_at_with_stale_index_is_none() {
        assert_eq!(MapModel::tile_at(&[], 10.0, 10.0), None);
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let tiles = m.layout(rect(100.0, 100.0));
        let hit = MapModel::tile_at(&tiles, 50.0, 50.0).unwrap();
        assert!(hit < tiles.len());
        assert!(tiles.get(tiles.len()).is_none());
    }

    #[test]
    fn category_paint_uses_the_nearest_finding() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let idx = scan(&[d.path()]);
        let f = finding(&idx, Category::AppCaches, &d.path().join("a"));
        let m = MapModel::new(wrap(idx, vec![f]), d.path().into(), NOW);
        let idx = &m.snapshot().index;
        let a = idx.find(&d.path().join("a")).unwrap();
        let one = idx.find(&d.path().join("a/one")).unwrap();
        let three = idx.find(&d.path().join("b/three")).unwrap();
        assert_eq!(m.paint_of(one), Paint::Category(Some(Category::AppCaches)));
        assert_eq!(m.paint_of(three), Paint::Category(None));
        assert_eq!(m.finding_index(one), Some(0));
        assert_eq!(m.direct_finding_index(one), None);
        assert_eq!(m.direct_finding_index(a), Some(0));
        assert_eq!(
            m.finding_of(one).map(|f| f.category),
            Some(Category::AppCaches)
        );
    }

    #[test]
    fn age_and_files_buckets() {
        assert_eq!(age_bucket(NOW - DAY, NOW), 0);
        assert_eq!(age_bucket(NOW - 100 * DAY, NOW), 1);
        assert_eq!(age_bucket(NOW - 300 * DAY, NOW), 2);
        assert_eq!(age_bucket(NOW - 400 * DAY, NOW), 3);
        assert_eq!(age_bucket(NOW - 800 * DAY, NOW), 4);
        assert_eq!(age_bucket(0, NOW), 5);
        assert_eq!(age_bucket(NOW + DAY, NOW), 0, "future counts as new");
        assert_eq!(files_bucket(1), 0);
        assert_eq!(files_bucket(10), 1);
        assert_eq!(files_bucket(11), 2);
        assert_eq!(files_bucket(1_000), 3);
        assert_eq!(files_bucket(10_000), 4);
        assert_eq!(files_bucket(10_001), 5);
    }

    #[test]
    fn exclude_removes_subtree_and_shrinks_ancestors() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let idx = m.snapshot().index.clone();
        let root = idx.roots[0];
        let a = idx.find(&d.path().join("a")).unwrap();
        let (a_alloc, a_logical, a_files) = {
            let n = idx.node(a);
            (n.agg_allocated, n.agg_logical, n.agg_files)
        };
        let before = m.weight(root);
        let (total_before, files_before) = m.totals();
        m.exclude(&[d.path().join("a"), d.path().join("missing")]);
        assert_eq!(m.weight(a), 0);
        assert_eq!(m.weight(root), before - a_alloc);
        assert_eq!(m.totals(), (total_before - a_alloc, files_before - a_files));
        assert!(tile_of(&m.layout(rect(600.0, 400.0)), a).is_none());
        // Excluding again (or something inside it) changes nothing.
        m.exclude(&[d.path().join("a"), d.path().join("a/one")]);
        assert_eq!(m.weight(root), before - a_alloc);
        m.set_weight_mode(WeightMode::Claimed);
        assert_eq!(m.weight(root), idx.node(root).agg_logical - a_logical);
    }

    #[test]
    fn set_snapshot_keeps_path_or_resets() {
        let d = tempfile::tempdir().unwrap();
        tree(d.path());
        let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
        let a_path = d.path().join("a");
        let a = m.snapshot().index.find(&a_path).unwrap();
        assert!(m.enter(a));
        m.exclude(&[d.path().join("a/one")]);
        let one = m.snapshot().index.find(&d.path().join("a/one")).unwrap();
        assert_eq!(m.weight(one), 0);

        m.set_snapshot(wrap(scan(&[d.path()]), vec![]));
        let idx = m.snapshot().index.clone();
        assert_eq!(idx.path(m.root().unwrap()), a_path);
        let one = idx.find(&d.path().join("a/one")).unwrap();
        assert!(m.weight(one) > 0, "exclusions are cleared");

        fs::remove_dir_all(&a_path).unwrap();
        m.set_snapshot(wrap(scan(&[d.path()]), vec![]));
        assert_eq!(m.root(), None);
    }

    #[test]
    fn tooltip_rows_for_a_sparse_file_and_a_rest_tile() {
        let d = tempfile::tempdir().unwrap();
        touch(&d.path().join("disk.img"), 100);
        let mut idx = scan(&[d.path()]);
        let f = idx.find(&d.path().join("disk.img")).unwrap();
        set_sizes(&mut idx, f, 4096, 1 << 30);
        flag(&mut idx, f, NodeFlags::SPARSE);
        let mut m = MapModel::new(wrap(idx, vec![]), d.path().into(), NOW);
        let root = m.snapshot().index.roots[0];
        assert!(m.enter(root));
        let tiles = m.layout(rect(300.0, 200.0));
        let t = tile_of(&tiles, f).expect("sparse tile");
        assert!(t.sparse);
        assert_eq!(t.label, "disk.img");
        let (title, rows) = m.tooltip(t);
        assert_eq!(title, "disk.img");
        let row = |k: &str| rows.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert_eq!(row("On disk"), Some(crate::format::bytes(4096)));
        assert_eq!(row("Claimed"), Some(crate::format::bytes(1 << 30)));
        assert_eq!(row("Flags"), Some("sparse".to_string()));
        assert_eq!(row("Files"), None);
        assert_eq!(row("Category"), None);

        let rest = Tile {
            node: None,
            rect: rect(10.0, 10.0),
            depth: 0,
            label: "3 more".into(),
            caption: None,
            paint: Paint::Rest,
            sparse: false,
            dashed: false,
            rest: Some((3, 12_000)),
            is_dir: false,
        };
        let (title, rows) = m.tooltip(&rest);
        assert_eq!(title, "3 more");
        assert_eq!(rows, vec![("On disk", crate::format::bytes(12_000))]);
    }
}
