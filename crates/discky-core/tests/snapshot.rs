mod fixtures;
use discky_core::{
    config::Thresholds,
    findings::Categorizer,
    fs::walk::{ScanOptions, walk},
    index::snapshot::{Actor, Snapshot, SnapshotError, SnapshotMeta},
    rules::RuleSet,
};

fn snap(root: &std::path::Path, actor: Actor) -> Snapshot {
    let index = walk(
        &ScanOptions {
            roots: vec![root.into()],
            exclude: globset::GlobSet::empty(),
            threads: 0,
            exact_private_size: false,
        },
        &|_| {},
    );
    let no_access = index.errors.iter().map(|e| e.path.clone()).collect();
    Snapshot {
        meta: SnapshotMeta {
            format_version: 1,
            created_at: 0,
            actor,
            roots: vec![root.into()],
            no_access,
            node_count: index.len() as u32,
        },
        index,
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
    s.save(&p).unwrap();
    let l = Snapshot::load(&p).unwrap();
    assert_eq!(l.meta, s.meta);
    assert_eq!(l.findings.len(), s.findings.len());
    for (a, b) in l.findings.iter().zip(&s.findings) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.path, b.path);
        assert_eq!(a.freed_if_deleted, b.freed_if_deleted);
        assert_eq!(a.removal, b.removal);
    }
}
