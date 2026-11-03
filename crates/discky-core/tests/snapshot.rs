mod fixtures;
use discky_core::{
    config::Thresholds,
    findings::Categorizer,
    fs::walk::{ScanOptions, walk},
    index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotError, SnapshotMeta},
    rules::RuleSet,
};

fn snap(root: &std::path::Path, actor: Actor) -> Snapshot {
    let index = walk(
        &ScanOptions {
            roots: vec![root.into()],
            exclude: globset::GlobSet::empty(),
            threads: 0,
            exact_private_size: false,
            cancel: None,
        },
        &|_| {},
    );
    let no_access = index.errors.iter().map(|e| e.path.clone()).collect();
    Snapshot {
        meta: SnapshotMeta {
            format_version: SNAPSHOT_FORMAT,
            created_at: 0,
            actor,
            roots: vec![root.into()],
            no_access,
            node_count: index.len() as u32,
            exact_private_size: false,
        },
        index: index.into(),
        findings: vec![],
    }
}

#[test]
fn roundtrip_preserves_nodes_and_meta() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let s = snap(d.path(), Actor::Mcp);
    let p = d.path().join("snapshot.bin");
    s.save(&p).unwrap();
    let l = Snapshot::load(&p).unwrap();
    assert_eq!(l.index.len(), s.index.len());
    assert_eq!(l.meta, s.meta);
    assert!(l.meta.no_access.iter().any(|x| x.ends_with("locked")));
    assert!(matches!(Snapshot::peek_meta(&p).unwrap().actor, Actor::Mcp));
    assert!(!p.with_extension("bin.tmp").exists());
}

#[test]
fn concurrent_saves_never_leave_a_corrupt_file() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let p = d.path().join("snapshot.bin");
    let a = snap(d.path(), Actor::App);
    let b = snap(d.path(), Actor::Mcp);
    std::thread::scope(|s| {
        for _ in 0..5 {
            s.spawn(|| a.save(&p).unwrap());
            s.spawn(|| b.save(&p).unwrap());
        }
    });
    assert!(Snapshot::load(&p).is_ok());
}

#[test]
fn wrong_magic_is_incompatible() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("snapshot.bin");
    std::fs::write(&p, b"GARBAGEGARBAGE").unwrap();
    assert!(matches!(
        Snapshot::load(&p),
        Err(SnapshotError::Incompatible)
    ));
    std::fs::write(&p, b"DISC").unwrap();
    assert!(matches!(
        Snapshot::peek_meta(&p),
        Err(SnapshotError::Incompatible)
    ));
}

#[test]
fn corrupt_meta_is_incompatible() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("snapshot.bin");
    let mut bytes = b"DISCKY01".to_vec();
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&[0xFF; 16]);
    std::fs::write(&p, &bytes).unwrap();
    assert!(matches!(
        Snapshot::load(&p),
        Err(SnapshotError::Incompatible)
    ));
    assert!(matches!(
        Snapshot::peek_meta(&p),
        Err(SnapshotError::Incompatible)
    ));
}

#[test]
fn roundtrip_preserves_findings() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let mut s = snap(d.path(), Actor::App);
    s.findings = Categorizer {
        index: &s.index,
        rules: &RuleSet::builtin(),
        thresholds: &Thresholds::default(),
    }
    .run_with_home(Some(d.path()));
    assert!(!s.findings.is_empty());
    let p = d.path().join("snapshot.bin");
    // `index` is an `Arc<Index>` in memory but saved as the plain `Index`.
    s.save(&p).unwrap();
    let l = Snapshot::load(&p).unwrap();
    assert_eq!(l.meta, s.meta);
    assert_eq!(l.index.len(), s.index.len());
    assert_eq!(l.findings.len(), s.findings.len());
    for (a, b) in l.findings.iter().zip(&s.findings) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.path, b.path);
        assert_eq!(a.freed_if_deleted, b.freed_if_deleted);
        assert_eq!(a.removal, b.removal);
    }
}

#[test]
fn format_2_roundtrips_exact_private_size() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let mut s = snap(d.path(), Actor::App);
    s.meta.exact_private_size = true;
    let p = d.path().join("snapshot.bin");
    s.save(&p).unwrap();
    let meta = Snapshot::peek_meta(&p).unwrap();
    assert_eq!(SNAPSHOT_FORMAT, 2);
    assert_eq!(meta.format_version, 2);
    assert!(meta.exact_private_size);
    assert!(Snapshot::load(&p).unwrap().meta.exact_private_size);
}

/// The format-1 meta layout, written by Milestone 1 builds.
#[derive(serde::Serialize)]
struct MetaV1 {
    format_version: u32,
    created_at: i64,
    actor: Actor,
    roots: Vec<std::path::PathBuf>,
    no_access: Vec<std::path::PathBuf>,
    node_count: u32,
}

#[test]
fn format_1_header_is_incompatible() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("snapshot.bin");
    let meta = postcard::to_stdvec(&MetaV1 {
        format_version: 1,
        created_at: 1,
        actor: Actor::Mcp,
        roots: vec![d.path().into()],
        no_access: vec![],
        node_count: 0,
    })
    .unwrap();
    let mut bytes = b"DISCKY01".to_vec();
    bytes.extend_from_slice(&(meta.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&meta);
    std::fs::write(&p, &bytes).unwrap();
    assert!(matches!(
        Snapshot::peek_meta(&p),
        Err(SnapshotError::Incompatible)
    ));
    assert!(matches!(
        Snapshot::load(&p),
        Err(SnapshotError::Incompatible)
    ));

    // The current layout with a stale version number is rejected too.
    let mut s = snap(d.path(), Actor::Mcp);
    s.meta.format_version = 1;
    s.save(&p).unwrap();
    assert!(matches!(
        Snapshot::peek_meta(&p),
        Err(SnapshotError::Incompatible)
    ));
}
