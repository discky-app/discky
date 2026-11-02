use discky_core::fs::attr::{ObjKind, is_sparse, read_dir_bulk};
use std::os::unix::fs::MetadataExt;

#[test]
fn reads_names_kinds_and_sizes() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("a.txt"), vec![7u8; 10_000]).unwrap();
    std::fs::create_dir(d.path().join("sub")).unwrap();
    std::os::unix::fs::symlink("a.txt", d.path().join("ln")).unwrap();
    let mut buf = Vec::new();
    let mut e = read_dir_bulk(d.path(), &mut buf).unwrap();
    e.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].name, "a.txt");
    assert!(matches!(e[0].kind, ObjKind::File));
    assert_eq!(e[0].logical, 10_000);
    assert_eq!(
        e[0].allocated,
        std::fs::metadata(d.path().join("a.txt")).unwrap().blocks() * 512
    );
    assert!(matches!(e[1].kind, ObjKind::Symlink));
    assert!(matches!(e[2].kind, ObjKind::Dir));
}

#[test]
fn sparse_file_reports_small_allocation() {
    let d = tempfile::tempdir().unwrap();
    let f = std::fs::File::create(d.path().join("disk.img")).unwrap();
    f.set_len(4 * 1024 * 1024 * 1024).unwrap(); // 4 GiB logical, ~0 allocated
    let mut buf = Vec::new();
    let e = read_dir_bulk(d.path(), &mut buf).unwrap();
    assert_eq!(e[0].logical, 4 * 1024 * 1024 * 1024);
    assert!(e[0].allocated < 1024 * 1024);
    assert!(is_sparse(e[0].logical, e[0].allocated));
    assert!(e[0].private.is_some(), "APFS should return PRIVATESIZE");
}

#[test]
fn hard_links_share_file_id_and_report_link_count() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("x"), b"hello").unwrap();
    std::fs::hard_link(d.path().join("x"), d.path().join("y")).unwrap();
    let mut buf = Vec::new();
    let e = read_dir_bulk(d.path(), &mut buf).unwrap();
    assert_eq!(e[0].file_id, e[1].file_id);
    assert_eq!(e[0].link_count, 2);
}

#[test]
fn unreadable_dir_is_an_error_not_a_panic() {
    assert!(read_dir_bulk(std::path::Path::new("/nonexistent-discky"), &mut Vec::new()).is_err());
}

#[test]
fn large_dir_spans_multiple_batches() {
    // ~3000 records of ~120 bytes exceed the 256 KiB buffer, forcing several syscalls.
    let d = tempfile::tempdir().unwrap();
    for i in 0..3000 {
        std::fs::write(
            d.path().join(format!("file-with-a-longish-name-{i:05}")),
            b"",
        )
        .unwrap();
    }
    let mut buf = Vec::new();
    let e = read_dir_bulk(d.path(), &mut buf).unwrap();
    assert_eq!(e.len(), 3000);
    assert!(
        e.iter()
            .all(|x| matches!(x.kind, ObjKind::File) && x.error.is_none())
    );
    let first = d.path().join(&e[0].name);
    assert_eq!(e[0].mtime, std::fs::metadata(first).unwrap().mtime());
}

#[test]
fn sparse_and_dataless_predicates() {
    use discky_core::fs::dataless::{SF_DATALESS, is_dataless};
    const GIB: u64 = 1 << 30;
    assert!(is_sparse(460 * GIB, 11 * GIB));
    assert!(!is_sparse(10 * GIB, 10 * GIB));
    assert!(!is_sparse(GIB / 2, 0), "gap under 1 GiB is not sparse");
    assert!(is_dataless(SF_DATALESS | 0x1));
    assert!(!is_dataless(0x1));
}

#[test]
fn set_no_materialize_succeeds() {
    discky_core::fs::dataless::set_no_materialize().unwrap();
}
