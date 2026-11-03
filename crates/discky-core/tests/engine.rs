mod fixtures;
use discky_core::plan::PlanId;
use discky_core::plan::execute::ExecuteError;
use discky_core::scan::{ScanEvent, ScanSink};
use discky_core::{
    DisckyPaths, Engine, EngineOptions, ExecuteRequest, index::snapshot::Actor, scan::ScanStatus,
};
use std::sync::{Arc, Mutex, mpsc};
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

/// Run every step, non-interactively, without progress events.
fn request() -> ExecuteRequest {
    ExecuteRequest {
        allow_interactive: false,
        only_steps: None,
        on_step: None,
    }
}

/// Options with every file inside `d` and a fake trash binary `d/fake-trash` that moves
/// its arguments into `d/trashed`, so the test never touches the real Trash.
fn temp_opts(d: &tempfile::TempDir) -> EngineOptions {
    let fake = d.path().join("fake-trash");
    let trashed = d.path().join("trashed");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nmkdir -p \"{0}\" && mv \"$@\" \"{0}\"/\n",
            trashed.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    EngineOptions {
        paths: DisckyPaths {
            config: d.path().join("c.toml"),
            snapshot: d.path().join("s.bin"),
            log: d.path().join("r.log"),
        },
        actor: Actor::App,
        trash_bin: fake,
    }
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
    assert!(
        e2.overview().exact_private_size.is_some(),
        "known for a snapshot loaded from disk"
    );
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
    let rep = e.execute_plan(&plan.id, request()).unwrap();
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
    e.execute_plan(&plan.id, request()).unwrap();
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

#[test]
fn open_with_uses_given_paths_and_trash_bin() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("tree");
    fixtures::build_tree(&root);
    let opts = temp_opts(&d);
    let e = {
        // Only `HOME` (for the build-dir pass) comes from the environment now.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HOME", std::env::temp_dir()) };
        Engine::open_with(opts).unwrap()
    };
    assert_eq!(e.paths().snapshot, d.path().join("s.bin"));
    assert_eq!(e.trash_bin(), d.path().join("fake-trash"));
    assert_ne!(
        e.trash_bin(),
        std::path::Path::new(discky_core::engine::TRASH_BIN)
    );
    let mut c = e.config();
    c.scan.roots = vec![root.clone()];
    c.removal.mode = discky_core::RemovalMode::Trash;
    e.set_config(c).unwrap();
    assert!(d.path().join("c.toml").exists());

    let id = e.start_scan(None);
    e.wait_scan(&id, Duration::from_secs(30));
    assert!(d.path().join("s.bin").exists());
    let nm = e
        .snapshot()
        .unwrap()
        .findings
        .iter()
        .find(|f| f.rule_id == "node-modules")
        .unwrap()
        .id
        .0
        .clone();
    let plan = e.plan(std::slice::from_ref(&nm)).unwrap();
    let rep = e.execute_plan(&plan.id, request()).unwrap();
    assert!(matches!(
        rep.results[0].status,
        discky_core::plan::execute::StepStatus::Done
    ));
    assert!(!root.join("web/node_modules").exists());
    assert!(d.path().join("trashed/node_modules/pkg/index.js").exists());
    assert_eq!(rep.log_path, d.path().join("r.log"));
}

#[test]
fn execute_plan_rejects_unknown_id() {
    let d = tempfile::tempdir().unwrap();
    let e = Engine::open_with(temp_opts(&d)).unwrap();
    let err = e
        .execute_plan(&PlanId("nope".into()), request())
        .unwrap_err();
    assert!(matches!(err, ExecuteError::UnknownPlan(_)));
}

/// [`temp_opts`] engine scanning `d/tree` (built by the fixture).
fn temp_engine(d: &tempfile::TempDir) -> Engine {
    let root = d.path().join("tree");
    if !root.exists() {
        fixtures::build_tree(&root);
    }
    let e = Engine::open_with(temp_opts(d)).unwrap();
    let mut c = e.config();
    c.scan.roots = vec![root];
    e.set_config(c).unwrap();
    e
}

/// A sink forwarding every event to the returned receiver.
fn channel_sink() -> (ScanSink, mpsc::Receiver<ScanEvent>) {
    let (tx, rx) = mpsc::channel();
    let sink: ScanSink = Arc::new(move |ev| {
        let _ = tx.send(ev);
    });
    (sink, rx)
}

/// A sink that forwards to `inner` (if any) and parks the scan on its first `Progress`
/// until the returned sender is dropped: the scan cannot finish before that, because
/// `walk` always reports progress at least once.
fn gated_sink(inner: Option<ScanSink>) -> (ScanSink, mpsc::Sender<()>) {
    let (release, gate) = mpsc::channel::<()>();
    let gate = Mutex::new(Some(gate));
    let sink: ScanSink = Arc::new(move |ev| {
        let first_progress = matches!(ev, ScanEvent::Progress(_));
        if let Some(inner) = &inner {
            inner(ev);
        }
        if first_progress && let Some(gate) = gate.lock().unwrap().take() {
            let _ = gate.recv_timeout(Duration::from_secs(30));
        }
    });
    (sink, release)
}

/// Every event `rx` gets until the scan drops its sinks (after `Finished`): the complete
/// event stream of that sink.
fn all_events(rx: &mpsc::Receiver<ScanEvent>) -> Vec<ScanEvent> {
    let mut events = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(ev) => events.push(ev),
            Err(mpsc::RecvTimeoutError::Disconnected) => return events,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("no Finished within 30 s: {events:?}"),
        }
    }
}

fn finished_count(events: &[ScanEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, ScanEvent::Finished(_)))
        .count()
}

#[test]
fn sink_receives_progress_then_exactly_one_finished() {
    let d = tempfile::tempdir().unwrap();
    let e = temp_engine(&d);
    let (sink, rx) = channel_sink();
    let id = e.start_scan_with(None, Some(sink));
    let events = all_events(&rx);
    assert!(matches!(
        events.last(),
        Some(ScanEvent::Finished(ScanStatus::Done { .. }))
    ));
    assert_eq!(finished_count(&events), 1);
    assert!(events.iter().any(|e| matches!(e, ScanEvent::Progress(_))));
    assert!(matches!(e.scan_status(&id), ScanStatus::Done { .. }));
}

#[test]
fn cancel_scan_yields_cancelled_and_no_snapshot_file() {
    let d = tempfile::tempdir().unwrap();
    let e = temp_engine(&d);
    let (sink, rx) = channel_sink();
    let (gated, release) = gated_sink(Some(sink));
    let id = e.start_scan_with(None, Some(gated));
    assert!(e.cancel_scan(&id), "a running scan accepts the cancel");
    drop(release);
    let events = all_events(&rx);
    assert_eq!(finished_count(&events), 1);
    assert!(
        matches!(
            events.last(),
            Some(ScanEvent::Finished(ScanStatus::Cancelled { .. }))
        ),
        "{events:?}"
    );
    let st = e.scan_status(&id);
    assert!(matches!(st, ScanStatus::Cancelled { .. }), "{st:?}");
    assert!(!e.paths().snapshot.exists());
    assert!(e.snapshot().is_none());
    assert!(!e.cancel_scan(&id), "a finished scan cannot be cancelled");
    assert!(!e.cancel_scan(&discky_core::scan::ScanId("nope".into())));
    let v = serde_json::to_value(&st).unwrap();
    assert_eq!(v["kind"], "cancelled");
}

#[test]
fn reload_snapshot_picks_up_newer_file() {
    let d = tempfile::tempdir().unwrap();
    let a = temp_engine(&d);
    let b = Engine::open_with(temp_opts(&d)).unwrap();
    assert!(b.snapshot_file_meta().is_none());
    assert!(matches!(b.reload_snapshot(), Ok(false)), "no file yet");
    let id = a.start_scan(None);
    assert!(matches!(
        a.wait_scan(&id, Duration::from_secs(30)),
        ScanStatus::Done { .. }
    ));
    assert!(b.snapshot().is_none());
    let meta = b.snapshot_file_meta().expect("a's snapshot is on disk");
    assert_eq!(meta.created_at, a.snapshot().unwrap().meta.created_at);
    assert!(matches!(b.reload_snapshot(), Ok(true)));
    assert_eq!(b.snapshot().unwrap().meta, a.snapshot().unwrap().meta);
    assert_eq!(
        b.overview().exact_private_size,
        Some(meta.exact_private_size),
        "known for a snapshot loaded from disk"
    );
    assert!(matches!(b.reload_snapshot(), Ok(false)), "not newer");
}

#[test]
fn joining_running_scan_delivers_current_progress() {
    let d = tempfile::tempdir().unwrap();
    let e = temp_engine(&d);
    let (gated, release) = gated_sink(None);
    let a = e.start_scan_with(None, Some(gated));
    let (sink, rx) = channel_sink();
    let b = e.start_scan_with(None, Some(sink));
    assert_eq!(a, b);
    drop(release);
    let events = all_events(&rx);
    assert!(
        matches!(events.first(), Some(ScanEvent::Progress(_))),
        "{events:?}"
    );
    assert_eq!(finished_count(&events), 1);
    assert!(matches!(
        events.last(),
        Some(ScanEvent::Finished(ScanStatus::Done { .. }))
    ));
}
