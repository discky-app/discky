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
        let mut m = MapModel {
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
        };
        m.reset_subtractions();
        m
    }

    /// Clears exclusions and seeds `subtracted` with every hard-link duplicate's logical
    /// size on each ancestor: the walker keeps `logical` on a duplicate (and so in
    /// `agg_logical`), but the shared bytes count once, under the first name.
    fn reset_subtractions(&mut self) {
        self.excluded.clear();
        self.subtracted.clear();
        let idx = &self.snap.index;
        for n in idx
            .nodes
            .iter()
            .filter(|n| n.flags.contains(NodeFlags::HARDLINK_DUP))
        {
            let mut cur = n.parent;
            while let Some(a) = cur {
                self.subtracted.entry(a).or_default().claimed += n.logical;
                cur = idx.node(a).parent;
            }
        }
    }

    pub fn snapshot(&self) -> &Arc<Snapshot> {
        &self.snap
    }

    /// Keeps the current folder when its path exists in the new index, else returns to the
    /// top; clears exclusions, unless the index is the same (a removal publishes the
    /// snapshot without the removed findings over the old index, still listing the removed
    /// paths).
    pub fn set_snapshot(&mut self, snap: Arc<Snapshot>) {
        let same_index = Arc::ptr_eq(&self.snap.index, &snap.index);
        let path = self.root.map(|r| self.snap.index.path(r));
        self.root = path
            .and_then(|p| snap.index.find(&p))
            .filter(|&n| snap.index.node(n).kind == ObjKind::Dir);
        self.findings = NodeFindings::build(&snap);
        self.snap = snap;
        if !same_index {
            self.reset_subtractions();
        }
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

    /// Shows `node` (`None` = the top); ids out of range or not a directory are ignored.
    pub fn go_to(&mut self, node: Option<NodeId>) {
        let idx = &self.snap.index;
        match node {
            Some(n) if (n.0 as usize) >= idx.len() || idx.node(n).kind != ObjKind::Dir => {}
            _ => self.root = node,
        }
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
    /// file count off every ancestor. Paths already hidden, or inside a hidden folder, are
    /// skipped. When the open folder becomes hidden, the map moves to its nearest visible
    /// ancestor, or the top.
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
        while let Some(r) = self.root.filter(|&r| self.is_hidden(r)) {
            self.root = self.snap.index.node(r).parent;
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

    /// Nested tiles of the current folder in `rect`: all siblings of a level, then each
    /// folder's children (a parent always before its children). A directory's children go
    /// in its rect inset by [`PAD`] below a [`HEADER_H`] label strip, only when the tile is
    /// at least `2·HEADER_H` tall and [`LABEL_MIN_W`] wide. Stops at [`MapModel::depth`]
    /// levels and [`MAX_TILES`] tiles.
    pub fn layout(&self, rect: Rect) -> Vec<Tile> {
        let top: Vec<NodeId> = match self.root {
            Some(r) => self.snap.index.children(r).collect(),
            None => self.snap.index.roots.clone(),
        };
        let mut out = Vec::new();
        self.lay_out(&top, rect, 0, &mut out);
        out
    }

    /// One level: every sibling's tile first, then each folder's children, so a large
    /// first sibling's subtree cannot use up the tile budget before its siblings get a tile.
    fn lay_out(&self, nodes: &[NodeId], rect: Rect, depth: u8, out: &mut Vec<Tile>) {
        if out.len() >= MAX_TILES {
            return;
        }
        let items: Vec<Item<NodeId>> = nodes
            .iter()
            .map(|&key| Item {
                key,
                weight: self.weight(key),
            })
            .collect();
        let mut nested = Vec::new();
        for placed in squarify(&items, rect) {
            if out.len() >= MAX_TILES {
                break;
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
                    if tile.is_dir
                        && depth + 1 < self.depth
                        && r.h >= 2.0 * HEADER_H
                        && r.w >= LABEL_MIN_W
                    {
                        nested.push((node, r));
                    }
                    out.push(tile);
                }
            }
        }
        for (node, r) in nested {
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

    fn tile(&self, node: NodeId, rect: Rect, depth: u8) -> Tile {
        let idx = &self.snap.index;
        let n = idx.node(node);
        let caption = if n.flags.contains(NodeFlags::DATALESS) {
            Some(CAPTION_CLOUD)
        } else if n.flags.contains(NodeFlags::NO_ACCESS) {
            Some(CAPTION_NO_ACCESS)
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
#[path = "model_tests.rs"]
mod tests;
