mod fixtures;
use discky_core::{Engine, index::snapshot::Actor, scan::ScanStatus};
use std::sync::Mutex;
use std::time::Duration;

/// `DISCKY_HOME` is process-wide; tests set it and open the engine under this lock (the
/// engine resolves its paths once, in `open`).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Point `DISCKY_HOME` at `d` and `HOME` at the system temp dir (the same value in every
/// test), so the test trees — all temp dirs — are under home, where the build-dir pass
/// looks.
fn set_env(d: &tempfile::TempDir) {
    unsafe {
        std::env::set_var("DISCKY_HOME", d.path());
        std::env::set_var("HOME", std::env::temp_dir());
    }
}

fn engine_in(d: &tempfile::TempDir) -> Engine {
    let e = {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_env(d);
        Engine::open(Actor::Mcp).unwrap()
    };
    let mut c = e.config();
    c.scan.roots = vec![d.path().join("tree")];
    e.set_config(c).unwrap();
    e
}

fn reopen(d: &tempfile::TempDir, actor: Actor) -> Engine {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_env(d);
    Engine::open(actor).unwrap()
}

#[test]
fn scan_runs_async_persists_and_is_reloaded() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    assert!(e.snapshot().is_none());
    let id = e.start_scan(None);
    assert!(matches!(
        e.scan_status(&id),
        ScanStatus::Running { .. } | ScanStatus::Done { .. }
    ));
    let st = e.wait_scan(&id, Duration::from_secs(30));
    assert!(matches!(st, ScanStatus::Done { findings, .. } if findings > 0));
    assert!(d.path().join("snapshot.bin").exists());
    assert!(e.overview().exact_private_size.is_some());
    drop(e);
    let e2 = reopen(&d, Actor::App);
    assert!(matches!(e2.snapshot().unwrap().meta.actor, Actor::Mcp));
    assert!(e2.last_error().is_none());
}

#[test]
fn second_start_while_running_returns_same_id_and_unknown_id_is_unknown() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    let a = e.start_scan(None);
    let b = e.start_scan(None);
    assert_eq!(a.0, b.0);
    e.wait_scan(&a, Duration::from_secs(30));
    assert!(matches!(
        e.scan_status(&discky_core::scan::ScanId("nope".into())),
        ScanStatus::Unknown
    ));
}

#[test]
fn plan_then_execute_updates_findings() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    let id = e.start_scan(None);
    e.wait_scan(&id, Duration::from_secs(30));
    let (f, _) = e.findings(
        Some(discky_core::rules::Category::ProjectBuilds),
        None,
        0,
        None,
        0,
        10,
    );
    let nm = f
        .iter()
        .find(|f| f.rule_id == "node-modules")
        .unwrap()
        .id
        .0
        .clone();
    let plan = e.plan(std::slice::from_ref(&nm)).unwrap();
    assert_eq!(plan.steps.len(), 1);
    let mut c = e.config();
    // Must stay Permanent (or set DISCKY_TRASH_BIN) so this never hits the real Trash.
    c.removal.mode = discky_core::RemovalMode::Permanent;
    e.set_config(c).unwrap();
    let plan = e.plan(std::slice::from_ref(&nm)).unwrap();
    let rep = e.execute(&plan, false, None).unwrap();
    assert!(matches!(
        rep.results[0].status,
        discky_core::plan::execute::StepStatus::Done
    ));
    assert!(
        e.inspect(&nm).unwrap().finding.is_none(),
        "finding removed after deletion"
    );
    assert_eq!(e.history(10).len(), 1);
}

#[test]
fn no_snapshot_queries_and_unknown_plan_ids() {
    let d = tempfile::tempdir().unwrap();
    let e = engine_in(&d);
    assert!(matches!(
        e.tree(d.path(), 10),
        Err(discky_core::EngineError::NoSnapshot)
    ));
    assert_eq!(e.findings(None, None, 0, None, 0, 10).1, 0);
    assert!(e.overview().exact_private_size.is_none());
    assert!(e.inspect("anything").is_none());
    assert!(e.history(10).is_empty());
}

#[test]
fn inspect_by_path_and_unknown_ids_are_skipped() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("tree");
    fixtures::build_tree(&root);
    let e = engine_in(&d);
    let id = e.start_scan(None);
    e.wait_scan(&id, Duration::from_secs(30));

    let ins = e.inspect(root.join("proj").to_str().unwrap()).unwrap();
    assert!(ins.in_snapshot);
    assert_eq!(ins.entry.as_ref().unwrap().path, root.join("proj"));
    assert!(ins.children.iter().any(|c| c.name == "target"));

    let target = e
        .inspect(root.join("proj/target").to_str().unwrap())
        .unwrap();
    let finding = target.finding.expect("proj/target is a finding");
    assert!(target.rule.is_some());

    // A repeated id is planned once, at its first position.
    let plan = e
        .plan(&[finding.id.0.clone(), "nope".into(), finding.id.0.clone()])
        .unwrap();
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.total_freed, finding.freed_if_deleted);
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].0.0, "nope");
    assert_eq!(e.get_plan(&plan.id).unwrap().id, plan.id);

    let none = e.inspect("/definitely/not/scanned").unwrap();
    assert!(!none.in_snapshot && none.finding.is_none() && none.entry.is_none());
}

#[test]
fn scan_status_serializes_with_kind_tag() {
    let v = serde_json::to_value(ScanStatus::Unknown).unwrap();
    assert_eq!(v["kind"], "unknown");
}

#[test]
fn execute_while_a_reader_holds_the_snapshot_shares_the_index() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    let id = e.start_scan(None);
    e.wait_scan(&id, Duration::from_secs(30));
    let mut c = e.config();
    // Must stay Permanent (or set DISCKY_TRASH_BIN) so this never hits the real Trash.
    c.removal.mode = discky_core::RemovalMode::Permanent;
    e.set_config(c).unwrap();
    let held = e.snapshot().unwrap();
    let nm = held
        .findings
        .iter()
        .find(|f| f.rule_id == "node-modules")
        .unwrap()
        .id
        .0
        .clone();
    let plan = e.plan(std::slice::from_ref(&nm)).unwrap();
    e.execute(&plan, false, None).unwrap();
    assert!(e.inspect(&nm).unwrap().finding.is_none());
    let now = e.snapshot().unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&held, &now),
        "a new snapshot is published"
    );
    assert!(
        std::sync::Arc::ptr_eq(&held.index, &now.index),
        "index shared, not cloned"
    );
    assert!(
        held.findings.iter().any(|f| f.id.0 == nm),
        "the held snapshot is unchanged"
    );
}

#[test]
fn reload_config_reads_the_file_without_writing_it() {
    let d = tempfile::tempdir().unwrap();
    let e = engine_in(&d);
    assert_eq!(e.config().removal.mode, discky_core::RemovalMode::Trash);
    let file = d.path().join("config.toml");
    let text = "[removal]\nmode = \"permanent\"\n";
    std::fs::write(&file, text).unwrap();
    e.reload_config().unwrap();
    assert_eq!(e.config().removal.mode, discky_core::RemovalMode::Permanent);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);

    std::fs::write(&file, "not toml [").unwrap();
    assert!(e.reload_config().is_err());
    assert_eq!(
        e.config().removal.mode,
        discky_core::RemovalMode::Permanent,
        "last good config kept"
    );
}
