mod fixtures;
use discky_core::{
    fs::walk::{ScanOptions, walk},
    index::NodeFlags,
};

fn opts(root: &std::path::Path) -> ScanOptions {
    ScanOptions {
        roots: vec![root.to_path_buf()],
        exclude: globset::GlobSet::empty(),
        threads: 0,
    }
}

#[test]
fn walk_counts_every_file_once_and_sums_allocated() {
    let d = tempfile::tempdir().unwrap();
    let fx = fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    assert_eq!(idx.roots.len(), 1);
    let root = idx.node(idx.roots[0]);
    assert_eq!(root.agg_files, fx.file_count);
    assert_eq!(
        root.agg_allocated, fx.allocated_total,
        "hard link counted once, sparse by blocks"
    );
}

#[test]
fn sparse_and_hardlink_flags_are_set() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    let big = idx.find(&d.path().join("big.bin")).unwrap();
    assert!(idx.node(big).flags.contains(NodeFlags::SPARSE));
    assert!(idx.node(big).logical > idx.node(big).allocated * 100);
    let a = idx.find(&d.path().join("linked/a")).unwrap();
    let b = idx.find(&d.path().join("linked/b")).unwrap();
    let dups = [a, b]
        .iter()
        .filter(|n| idx.node(**n).flags.contains(NodeFlags::HARDLINK_DUP))
        .count();
    assert_eq!(dups, 1);
}

#[test]
fn unreadable_dir_is_flagged_and_reported_not_fatal() {
    let d = tempfile::tempdir().unwrap();
    let _fx = fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    let locked = idx.find(&d.path().join("locked")).unwrap();
    assert!(idx.node(locked).flags.contains(NodeFlags::NO_ACCESS));
    assert!(
        idx.errors
            .iter()
            .any(|e| e.path.ends_with("locked") && e.errno == libc::EACCES)
    );
}

#[test]
fn path_roundtrip_and_children() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    let t = idx.find(&d.path().join("proj/target")).unwrap();
    assert_eq!(idx.path(t), d.path().join("proj/target"));
    let proj = idx.find(&d.path().join("proj")).unwrap();
    assert!(idx.children(proj).any(|c| c == t));
}

#[test]
fn exclude_glob_prunes_subtree() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let mut b = globset::GlobSetBuilder::new();
    b.add(globset::Glob::new("**/node_modules").unwrap());
    let o = ScanOptions {
        exclude: b.build().unwrap(),
        ..opts(d.path())
    };
    let idx = walk(&o, &|_| {});
    assert!(idx.find(&d.path().join("web/node_modules")).is_none());
}

#[test]
#[ignore]
fn home_scan_throughput() {
    let home = std::env::var("HOME").unwrap();
    let t = std::time::Instant::now();
    let idx = walk(&opts(std::path::Path::new(&home)), &|_| {});
    let secs = t.elapsed().as_secs_f64();
    eprintln!(
        "{} nodes in {:.1}s = {:.0} files/s",
        idx.len(),
        secs,
        idx.len() as f64 / secs
    );
    assert!(idx.len() as f64 / secs > 150_000.0);
}

#[test]
fn clone_is_flagged_and_its_private_size_fetched() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("orig"), vec![7u8; 1 << 20]).unwrap();
    let st = std::process::Command::new("cp")
        .arg("-c")
        .arg(d.path().join("orig"))
        .arg(d.path().join("clone"))
        .status()
        .unwrap();
    assert!(st.success(), "cp -c (clonefile) needs APFS");
    let idx = walk(&opts(d.path()), &|_| {});
    let c = idx.node(idx.find(&d.path().join("clone")).unwrap());
    assert!(c.flags.contains(NodeFlags::CLONE_SHARED));
    assert!(c.allocated >= 1 << 20);
    assert!(c.private < c.allocated, "fully shared clone frees ~nothing");
}
