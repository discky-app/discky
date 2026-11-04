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
    // The dashed tile keeps its logical size, but the total counts only what is on disk.
    assert_eq!(m.totals().0, local_logical);
    m.set_weight_mode(WeightMode::OnDisk);
    assert_eq!(m.totals().0, local_alloc);
}

#[test]
fn claimed_total_leaves_out_cloud_bytes_below_and_after_exclusion() {
    let d = tempfile::tempdir().unwrap();
    touch(&d.path().join("docs/local"), 10_000);
    touch(&d.path().join("docs/cloud"), 10);
    touch(&d.path().join("other"), 5_000);
    let mut idx = scan(&[d.path()]);
    let cloud = idx.find(&d.path().join("docs/cloud")).unwrap();
    let docs = idx.find(&d.path().join("docs")).unwrap();
    set_sizes(&mut idx, cloud, 0, 1 << 20);
    flag(&mut idx, cloud, NodeFlags::DATALESS);
    let other_logical = idx.node(idx.find(&d.path().join("other")).unwrap()).logical;
    let local_logical = idx
        .node(idx.find(&d.path().join("docs/local")).unwrap())
        .logical;
    let mut m = MapModel::new(wrap(idx, vec![]), d.path().into(), NOW);
    m.set_weight_mode(WeightMode::Claimed);
    let root = m.snapshot().index.roots[0];
    assert!(m.enter(root));
    assert_eq!(m.weight(docs), local_logical + (1 << 20));
    assert_eq!(m.totals().0, local_logical + other_logical);
    assert!(m.enter(docs));
    assert_eq!(m.totals().0, local_logical);
    m.exclude(&[d.path().join("docs")]);
    assert_eq!(m.root(), Some(root));
    assert_eq!(m.totals().0, other_logical);
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
    // The folder counts the shared bytes once under Claimed, not once per name.
    let idx = m.snapshot().index.clone();
    let orig = idx.children(root).find(|&c| c != dup).unwrap();
    let orig_logical = idx.node(orig).logical;
    assert!(idx.node(dup).logical > 0);
    assert_eq!(m.weight(root), orig_logical);
    assert_eq!(m.totals().0, orig_logical);
    // Still true after an exclusion and a rescan.
    m.exclude(&[d.path().join("missing")]);
    assert_eq!(m.weight(root), orig_logical);
    m.set_snapshot(m.snapshot().clone());
    assert_eq!(m.weight(root), orig_logical);
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
    let idx = m.snapshot().index.clone();
    let kids: Vec<_> = tiles
        .iter()
        .enumerate()
        .filter(|(_, t)| t.node.is_some_and(|n| idx.node(n).parent == Some(a)))
        .collect();
    assert!(kids.iter().all(|&(i, _)| i > pos), "parent before children");
    let kids: Vec<_> = kids.into_iter().map(|(_, t)| t).collect();
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
    // The cap never costs a shallower level its tiles: every folder still has one.
    m.set_depth(1);
    let top = m.layout(rect(800.0, 600.0)).len();
    assert_eq!(top, 16);
    assert_eq!(tiles.iter().filter(|t| t.depth == 0).count(), top);
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
fn set_snapshot_with_the_same_index_keeps_exclusions() {
    let d = tempfile::tempdir().unwrap();
    tree(d.path());
    let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
    let root = m.snapshot().index.roots[0];
    let before = m.weight(root);
    m.exclude(&[d.path().join("a")]);
    let shrunk = m.weight(root);
    assert!(shrunk < before);
    // A removal publishes a snapshot with fewer findings over the same index.
    let trimmed = Arc::new(Snapshot {
        meta: m.snapshot().meta.clone(),
        index: Arc::clone(&m.snapshot().index),
        findings: vec![],
    });
    m.set_snapshot(trimmed);
    assert_eq!(m.weight(root), shrunk);
    let a = m.snapshot().index.find(&d.path().join("a")).unwrap();
    assert_eq!(m.weight(a), 0);
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

#[test]
fn excluding_the_open_folder_moves_up() {
    let d = tempfile::tempdir().unwrap();
    tree(d.path());
    touch(&d.path().join("a/deep/x"), 3_000);
    let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
    let idx = m.snapshot().index.clone();
    let root = idx.roots[0];
    let a = idx.find(&d.path().join("a")).unwrap();
    let deep = idx.find(&d.path().join("a/deep")).unwrap();
    assert!(m.enter(deep));
    m.exclude(&[d.path().join("a")]);
    assert_eq!(m.root(), Some(root), "nearest visible ancestor");
    assert!(tile_of(&m.layout(rect(600.0, 400.0)), a).is_none());
    m.exclude(&[d.path().to_path_buf()]);
    assert_eq!(m.root(), None, "no visible ancestor: the top");
}

#[test]
fn go_to_ignores_stale_or_non_folder_ids() {
    let d = tempfile::tempdir().unwrap();
    tree(d.path());
    let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
    let a = m.snapshot().index.find(&d.path().join("a")).unwrap();
    let top = m.snapshot().index.find(&d.path().join("top")).unwrap();
    m.go_to(Some(a));
    m.go_to(Some(NodeId(u32::MAX)));
    m.go_to(Some(top));
    assert_eq!(m.root(), Some(a));
}

#[test]
fn enter_refuses_a_folder_whose_children_weigh_nothing() {
    let d = tempfile::tempdir().unwrap();
    tree(d.path());
    touch(&d.path().join("empty/nothing"), 0);
    let mut m = MapModel::new(wrap(scan(&[d.path()]), vec![]), d.path().into(), NOW);
    let empty = m.snapshot().index.find(&d.path().join("empty")).unwrap();
    assert!(!m.enter(empty));
    assert_eq!(m.root(), None);
}
