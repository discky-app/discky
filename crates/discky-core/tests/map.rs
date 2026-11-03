use std::fs;
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use discky_core::findings::app_caches::owner_of;
use discky_core::{
    DisckyPaths, Engine, EngineOptions, ScanEvent, ScanSink,
    findings::{Component, ComponentKind, ComponentRemoval, Finding, FindingId, Removal},
    fs::walk::{ScanOptions, walk},
    index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotMeta},
    query::NodeFindings,
    rules::{Category, SafetyLabel},
};

fn touch(p: &Path, bytes: usize) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, vec![b'x'; bytes]).unwrap();
}

fn snap(root: &Path) -> Snapshot {
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
    Snapshot {
        meta: SnapshotMeta {
            format_version: SNAPSHOT_FORMAT,
            created_at: 0,
            actor: Actor::App,
            roots: vec![root.into()],
            no_access: vec![],
            node_count: index.len() as u32,
            exact_private_size: false,
        },
        index: index.into(),
        findings: vec![],
    }
}

fn finding(s: &Snapshot, category: Category, path: &Path, components: Vec<Component>) -> Finding {
    Finding {
        id: FindingId::for_path(path),
        category,
        title: "t".into(),
        subtitle: None,
        path: Some(path.into()),
        node: s.index.find(path),
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
        components,
    }
}

#[test]
fn owner_is_self_then_nearest_ancestor() {
    let d = tempfile::tempdir().unwrap();
    let app = d.path().join("Caches/com.example.App");
    touch(&app.join("sub/file"), 10);
    let mut s = snap(d.path());
    s.findings
        .push(finding(&s, Category::AppCaches, &app, vec![]));
    let nf = NodeFindings::build(&s);
    let id = |p: &Path| s.index.find(p).unwrap();
    assert_eq!(nf.len(), 1);
    assert_eq!(nf.direct(id(&app)), Some(0));
    assert_eq!(nf.owner(&s.index, id(&app.join("sub"))), Some(0));
    assert_eq!(nf.owner(&s.index, id(&app.join("sub/file"))), Some(0));
    assert_eq!(nf.owner(&s.index, id(&d.path().join("Caches"))), None);
    assert_eq!(nf.direct(id(&app.join("sub"))), None);
}

#[test]
fn component_paths_are_mapped_for_path_less_findings() {
    let d = tempfile::tempdir().unwrap();
    let logs = d.path().join("Library/Logs/Foo");
    touch(&logs.join("a.log"), 10);
    let mut s = snap(d.path());
    let comp = Component {
        kind: ComponentKind::Logs,
        title: "Logs".into(),
        path: Some(logs.clone()),
        allocated: 1,
        freed_if_deleted: 1,
        modified: None,
        default_on: true,
        removal: ComponentRemoval::Trash,
        note: None,
        covered_by_cask: false,
    };
    let mut f = finding(&s, Category::Apps, &d.path().join("Gone.app"), vec![comp]);
    f.node = None;
    s.findings.push(f);
    let nf = NodeFindings::build(&s);
    assert_eq!(nf.owner(&s.index, s.index.find(&logs).unwrap()), Some(0));
    assert_eq!(
        nf.owner(&s.index, s.index.find(&logs.join("a.log")).unwrap()),
        Some(0)
    );
}

#[test]
fn descendant_finding_wins_over_the_container() {
    let d = tempfile::tempdir().unwrap();
    let vendor = d.path().join("AppSupport/Vendor");
    let m1 = vendor.join("models/m1");
    touch(&m1.join("blob"), 10);
    touch(&vendor.join("other/x"), 10);
    let mut s = snap(d.path());
    s.findings
        .push(finding(&s, Category::AppCaches, &vendor, vec![]));
    s.findings.push(finding(&s, Category::Models, &m1, vec![]));
    let nf = NodeFindings::build(&s);
    let id = |p: &Path| s.index.find(p).unwrap();
    assert_eq!(nf.owner(&s.index, id(&m1.join("blob"))), Some(1));
    assert_eq!(nf.owner(&s.index, id(&vendor.join("other"))), Some(0));
}

#[test]
fn inspect_names_the_owner_app_for_library_containers() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    let dir = home.join("Library/Caches/com.google.Chrome");
    touch(&dir.join("x"), 10);
    let trash = d.path().join("fake-trash");
    fs::write(&trash, "#!/bin/sh\n").unwrap();
    let e = Engine::open_with(EngineOptions {
        paths: DisckyPaths {
            config: d.path().join("c.toml"),
            snapshot: d.path().join("s.bin"),
            log: d.path().join("r.log"),
        },
        actor: Actor::App,
        trash_bin: trash,
    })
    .unwrap();
    let mut c = e.config();
    c.scan.roots = vec![home.clone()];
    e.set_config(c).unwrap();
    let (tx, rx) = mpsc::channel();
    let sink: ScanSink = Arc::new(move |ev| {
        let _ = tx.send(ev);
    });
    e.start_scan_with(None, Some(sink));
    let mut finished = false;
    while let Ok(ev) = rx.recv_timeout(Duration::from_secs(30)) {
        finished |= matches!(ev, ScanEvent::Finished(_));
    }
    assert!(finished);
    let got = e.inspect(dir.to_str().unwrap()).unwrap();
    assert_eq!(
        got.owner_app,
        Some(owner_of("Caches", "com.google.Chrome").app_name)
    );
}
