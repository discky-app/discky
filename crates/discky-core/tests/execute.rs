use discky_core::{
    DisckyPaths,
    config::Config,
    findings::{Finding, FindingId, Removal},
    history,
    index::snapshot::Actor,
    plan::{
        execute::{ExecuteError, ExecuteOptions, StepEvent, StepSink, StepStatus, execute_plan},
        plan_removal,
    },
    rules::{Category, SafetyLabel},
};

/// A temp dir, Discky paths inside it, and a fake trash binary that `mv`s its arguments
/// into `<tmp>/trashed`, so tests never touch the real Trash.
fn setup() -> (tempfile::TempDir, DisckyPaths, std::path::PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let bin = d.path().join("trash");
    let bin_dir = d.path().join("trashed");
    std::fs::create_dir(&bin_dir).unwrap();
    std::fs::write(
        &bin,
        format!("#!/bin/sh\nmv \"$@\" \"{}\"/\n", bin_dir.display()),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    // Built directly rather than via `DISCKY_HOME` + `resolve()`: tests run in parallel
    // threads and a process-wide env var would race between them.
    let paths = DisckyPaths {
        config: d.path().join("config.toml"),
        snapshot: d.path().join("snapshot.bin"),
        log: d.path().join("logs/removals.log"),
    };
    (d, paths, bin)
}

fn trash_finding(p: &std::path::Path) -> Finding {
    Finding {
        id: FindingId("f1".into()),
        category: Category::AppCaches,
        title: "c".into(),
        subtitle: None,
        path: Some(p.into()),
        node: None,
        allocated: 4096,
        logical: 4096,
        freed_if_deleted: 4096,
        modified: None,
        label: SafetyLabel::Regenerates,
        rule_id: "r".into(),
        explain: String::new(),
        removal: Removal::Trash {
            paths: vec![p.into()],
        },
        flags: vec![],
        components: Vec::new(),
    }
}

fn opts(actor: Actor, bin: std::path::PathBuf) -> ExecuteOptions {
    ExecuteOptions {
        allow_interactive: false,
        only_steps: None,
        actor,
        trash_bin: bin,
        on_step: None,
    }
}

/// A sink that records every event, and the events it recorded.
fn recording_sink() -> (StepSink, std::sync::Arc<std::sync::Mutex<Vec<StepEvent>>>) {
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink_events = std::sync::Arc::clone(&events);
    let sink: StepSink = std::sync::Arc::new(move |e| sink_events.lock().unwrap().push(e));
    (sink, events)
}

#[test]
fn trash_step_moves_dir_and_logs_history() {
    let (d, paths, bin) = setup();
    let target = d.path().join("cache");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("x"), [0u8; 4096]).unwrap();
    let plan = plan_removal(&[&trash_finding(&target)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::Mcp, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert!(!target.exists());
    assert!(d.path().join("trashed/cache").exists());
    assert!(rep.freed_total >= 4096);
    assert_eq!(rep.trashed_bytes, 4096);
    assert_eq!(rep.log_path, paths.log);
    let h = history::read(&paths, 10).unwrap();
    assert_eq!(h.len(), 1);
    assert!(matches!(h[0].actor, Actor::Mcp));
    assert!(matches!(h[0].status, StepStatus::Done));
    assert_eq!(h[0].paths, vec![target.clone()]);
    assert!(h[0].trash_paths[0].ends_with(".Trash/cache"));
}

#[test]
fn stale_plan_is_refused() {
    let (d, paths, bin) = setup();
    let target = d.path().join("cache");
    std::fs::create_dir(&target).unwrap();
    let plan = plan_removal(&[&trash_finding(&target)], &Config::default());
    std::fs::remove_dir(&target).unwrap();
    let e = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap_err();
    assert!(matches!(e, ExecuteError::PlanStale { path } if path == target));
    assert!(history::read(&paths, 10).unwrap().is_empty());
}

#[test]
fn failed_command_stops_the_plan() {
    let (d, paths, bin) = setup();
    let later = d.path().join("later");
    std::fs::create_dir(&later).unwrap();
    let f1 = Finding {
        removal: Removal::Command {
            tool: "sh".into(),
            argv: vec!["sh".into(), "-c".into(), "echo boom; exit 3".into()],
            cwd: None,
            install_hint: None,
            freed_note: None,
        },
        path: None,
        ..trash_finding(&d.path().join("nope"))
    };
    let f2 = trash_finding(&later);
    let plan = plan_removal(&[&f1, &f2], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Failed));
    assert!(rep.results[0].output.contains("boom"));
    assert!(matches!(rep.results[1].status, StepStatus::NotRun));
    assert_eq!(rep.stopped_at, Some(0));
    assert_eq!(rep.freed_total, 0);
    assert!(later.exists());
    let h = history::read(&paths, 10).unwrap();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].argv.as_ref().unwrap()[1], "-c");
}

#[test]
fn step_events_arrive_in_order() {
    let (d, paths, bin) = setup();
    let dirs: Vec<_> = ["a", "b", "c"].iter().map(|n| d.path().join(n)).collect();
    for p in &dirs {
        std::fs::create_dir(p).unwrap();
    }
    let findings: Vec<Finding> = dirs
        .iter()
        .enumerate()
        .map(|(i, p)| Finding {
            id: FindingId(format!("f{i}")),
            ..trash_finding(p)
        })
        .collect();
    let plan = plan_removal(&findings.iter().collect::<Vec<_>>(), &Config::default());
    let (sink, events) = recording_sink();
    let mut o = opts(Actor::App, bin);
    o.only_steps = Some(vec![0, 1]);
    o.on_step = Some(sink);
    let rep = execute_plan(&plan, &o, &paths).unwrap();
    let events = events.lock().unwrap();
    // The unselected (`NotRun`) step emits nothing.
    assert_eq!(events.len(), 4, "{events:?}");
    assert!(matches!(events[0], StepEvent::Started { index: 0 }));
    let StepEvent::Finished(r0) = &events[1] else {
        panic!("{:?}", events[1])
    };
    assert_eq!(r0.index, 0);
    assert_eq!(r0.status, StepStatus::Done);
    assert_eq!(r0.freed, rep.results[0].freed);
    assert!(matches!(events[2], StepEvent::Started { index: 1 }));
    let StepEvent::Finished(r1) = &events[3] else {
        panic!("{:?}", events[3])
    };
    assert_eq!(r1.index, 1);
    assert_eq!(r1.status, StepStatus::Done);
    assert_eq!(rep.results[2].status, StepStatus::NotRun);
}

#[test]
fn finished_event_carries_the_history_failure_reason() {
    let (d, paths, bin) = setup();
    // As in `failed_history_write_stops_the_plan_but_returns_the_report`: the step
    // replaces the log file with a directory, so the append right after it fails.
    let log = paths.log.display().to_string();
    let f1 = command_finding(d.path(), &format!("rm -f '{log}' && mkdir '{log}'"), None);
    let plan = plan_removal(&[&f1], &Config::default());
    let (sink, events) = recording_sink();
    let mut o = opts(Actor::App, bin);
    o.on_step = Some(sink);
    let rep = execute_plan(&plan, &o, &paths).unwrap();
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2, "{events:?}");
    let StepEvent::Finished(r) = &events[1] else {
        panic!("{events:?}")
    };
    assert!(
        r.reason
            .as_deref()
            .unwrap()
            .starts_with("History write failed:")
    );
    assert_eq!(r.reason, rep.results[0].reason);
}

#[test]
fn a_panicking_sink_does_not_stop_the_plan() {
    let (d, paths, bin) = setup();
    let a = d.path().join("a");
    let b = d.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let fb = Finding {
        id: FindingId("f2".into()),
        ..trash_finding(&b)
    };
    let plan = plan_removal(&[&trash_finding(&a), &fb], &Config::default());
    let mut o = opts(Actor::App, bin);
    o.on_step = Some(std::sync::Arc::new(|_| panic!("sink panic")));
    let rep = execute_plan(&plan, &o, &paths).unwrap();
    assert_eq!(rep.results[0].status, StepStatus::Done);
    assert_eq!(rep.results[1].status, StepStatus::Done);
    assert!(!a.exists() && !b.exists());
}

#[test]
fn interactive_trash_is_skipped_without_permission() {
    let (d, paths, bin) = setup();
    // Inside a read-only dir: removing it would need an admin prompt.
    let ro = d.path().join("ro");
    let x = ro.join("x");
    std::fs::create_dir_all(&x).unwrap();
    std::fs::set_permissions(&ro, std::os::unix::fs::PermissionsExt::from_mode(0o555)).unwrap();
    let plan = plan_removal(&[&trash_finding(&x)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::Mcp, bin), &paths);
    std::fs::set_permissions(&ro, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let rep = rep.unwrap();
    assert!(x.exists());
    assert!(matches!(rep.results[0].status, StepStatus::Skipped));
    assert!(
        rep.results[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("Discky.app")
    );
    assert_eq!(rep.stopped_at, None);
}

#[test]
fn only_steps_runs_only_the_selection() {
    let (d, paths, bin) = setup();
    let a = d.path().join("a");
    let b = d.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let fb = Finding {
        id: FindingId("f2".into()),
        ..trash_finding(&b)
    };
    let plan = plan_removal(&[&trash_finding(&a), &fb], &Config::default());
    // A stale step that is not selected does not block the run.
    std::fs::remove_dir(&a).unwrap();
    let mut o = opts(Actor::App, bin);
    o.only_steps = Some(vec![1]);
    let rep = execute_plan(&plan, &o, &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::NotRun));
    assert!(matches!(rep.results[1].status, StepStatus::Done));
    assert!(!b.exists());
    let recorded = history::read(&paths, 10).unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].step, 1);
}

#[test]
fn in_trash_lists_recorded_items_that_still_exist_once() {
    let (d, paths, _bin) = setup();
    let kept = d.path().join("kept");
    std::fs::create_dir(&kept).unwrap();
    std::fs::write(kept.join("f"), [1u8; 8192]).unwrap();
    let rec = |step: usize, trash_paths: Vec<std::path::PathBuf>| history::HistoryRecord {
        ts: step as i64,
        actor: Actor::App,
        plan: discky_core::plan::PlanId("p".into()),
        step,
        kind: "trash".into(),
        paths: vec![],
        argv: None,
        status: StepStatus::Done,
        freed: 0,
        output_tail: String::new(),
        trash_paths,
        reason: None,
    };
    history::append(
        &paths,
        &rec(0, vec![kept.clone(), d.path().join("emptied")]),
    )
    .unwrap();
    history::append(&paths, &rec(1, vec![kept.clone()])).unwrap();
    let listed = history::in_trash(&paths).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, kept);
    assert!(listed[0].1 >= 8192);
    let newest = history::read(&paths, 1).unwrap();
    assert_eq!(newest[0].step, 1);
}

#[test]
fn trash_that_leaves_the_path_in_place_fails() {
    let (d, paths, _bin) = setup();
    let noop = d.path().join("noop-trash");
    std::fs::write(
        &noop,
        "#!/bin/sh
exit 0
",
    )
    .unwrap();
    std::fs::set_permissions(&noop, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let target = d.path().join("cache");
    std::fs::create_dir(&target).unwrap();
    let plan = plan_removal(&[&trash_finding(&target)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, noop), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Failed));
    assert!(
        rep.results[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("Still present")
    );
    assert_eq!((rep.freed_total, rep.trashed_bytes), (0, 0));
    assert_eq!(rep.stopped_at, Some(0));
}

#[test]
fn missing_tool_fails_and_stops() {
    let (d, paths, bin) = setup();
    let later = d.path().join("later");
    std::fs::create_dir(&later).unwrap();
    let f1 = Finding {
        removal: Removal::Command {
            tool: "discky-no-such-tool".into(),
            argv: vec!["discky-no-such-tool".into(), "clean".into()],
            cwd: None,
            install_hint: Some("Install it.".into()),
            freed_note: None,
        },
        path: None,
        ..trash_finding(&d.path().join("nope"))
    };
    let plan = plan_removal(&[&f1, &trash_finding(&later)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Failed));
    assert!(
        rep.results[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("not found")
    );
    assert!(matches!(rep.results[1].status, StepStatus::NotRun));
    assert!(later.exists());
}

#[test]
fn remove_step_deletes_and_never_follows_symlinks() {
    let (d, paths, bin) = setup();
    let keep = d.path().join("keep");
    std::fs::create_dir(&keep).unwrap();
    std::fs::write(keep.join("data"), b"x").unwrap();
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&keep, &link).unwrap();
    let dir = d.path().join("dir");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("y"), b"y").unwrap();
    let f = Finding {
        removal: Removal::Trash {
            paths: vec![link.clone(), dir.clone()],
        },
        ..trash_finding(&link)
    };
    let mut cfg = Config::default();
    cfg.removal.mode = discky_core::RemovalMode::Permanent;
    let plan = plan_removal(&[&f], &cfg);
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert_eq!(rep.trashed_bytes, 0);
    assert!(std::fs::symlink_metadata(&link).is_err());
    assert!(!dir.exists());
    assert!(keep.join("data").exists());
}

fn command_finding(d: &std::path::Path, script: &str, cwd: Option<std::path::PathBuf>) -> Finding {
    Finding {
        removal: Removal::Command {
            tool: "sh".into(),
            argv: vec!["sh".into(), "-c".into(), script.into()],
            cwd,
            install_hint: None,
            freed_note: None,
        },
        path: None,
        ..trash_finding(&d.join("nope"))
    }
}

#[test]
fn failed_history_write_stops_the_plan_but_returns_the_report() {
    let (d, paths, bin) = setup();
    let later = d.path().join("later");
    std::fs::create_dir(&later).unwrap();
    // Step 0 replaces the (already opened-and-checked) log file with a directory, so the
    // append right after it fails.
    let log = paths.log.display().to_string();
    let f1 = command_finding(d.path(), &format!("rm -f '{log}' && mkdir '{log}'"), None);
    let plan = plan_removal(&[&f1, &trash_finding(&later)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    let reason = rep.results[0].reason.as_deref().unwrap();
    assert!(reason.starts_with("History write failed:"), "{reason}");
    assert!(reason.ends_with("; stopping"));
    assert_eq!(rep.stopped_at, Some(0));
    assert!(matches!(rep.results[1].status, StepStatus::NotRun));
    assert!(later.exists());
}

/// A plan for `f` made while its paths existed, then the paths removed behind its back
/// and the fingerprints re-taken, as if they had been missing at planning time but
/// planned anyway (planning itself skips such findings).
fn plan_then_vanish(f: &Finding, cfg: &Config) -> discky_core::plan::Plan {
    let mut plan = plan_removal(&[f], cfg);
    assert_eq!(plan.steps.len(), 1);
    for fp in &mut plan.steps[0].fingerprints {
        std::fs::remove_dir_all(&fp.path).unwrap();
        *fp = discky_core::plan::Fingerprint::take(&fp.path);
        assert!(!fp.exists);
    }
    plan
}

#[test]
fn trash_of_an_already_missing_path_is_done_frees_nothing_and_skips_trash() {
    let (d, paths, bin) = setup();
    let missing = d.path().join("gone-before-running");
    std::fs::create_dir(&missing).unwrap();
    let plan = plan_then_vanish(&trash_finding(&missing), &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert_eq!(rep.results[0].reason.as_deref(), Some("already absent"));
    assert_eq!(rep.results[0].freed, 0);
    assert_eq!((rep.freed_total, rep.trashed_bytes), (0, 0));
    assert_eq!(
        std::fs::read_dir(d.path().join("trashed")).unwrap().count(),
        0
    );
    let h = history::read(&paths, 1).unwrap();
    assert_eq!(h[0].reason.as_deref(), Some("already absent"));
    assert_eq!(h[0].freed, 0);
    assert!(h[0].trash_paths.is_empty());
}

#[test]
fn remove_of_an_already_missing_path_is_done_and_frees_nothing() {
    let (d, paths, bin) = setup();
    let missing = d.path().join("gone");
    std::fs::create_dir(&missing).unwrap();
    let mut cfg = Config::default();
    cfg.removal.mode = discky_core::RemovalMode::Permanent;
    let plan = plan_then_vanish(&trash_finding(&missing), &cfg);
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert_eq!(rep.results[0].reason.as_deref(), Some("already absent"));
    assert_eq!(rep.freed_total, 0);
}

#[test]
fn findings_already_gone_at_planning_are_skipped_and_not_counted() {
    let d = tempfile::tempdir().unwrap();
    let present = d.path().join("present");
    std::fs::create_dir(&present).unwrap();
    let gone = Finding {
        id: FindingId("gone".into()),
        ..trash_finding(&d.path().join("gone"))
    };
    let gone_cmd = Finding {
        id: FindingId("gone-cmd".into()),
        removal: Removal::Command {
            tool: "sh".into(),
            argv: vec!["sh".into(), "-c".into(), "true".into()],
            cwd: None,
            install_hint: None,
            freed_note: None,
        },
        ..trash_finding(&d.path().join("gone-too"))
    };
    let plan = plan_removal(
        &[&gone, &trash_finding(&present), &gone_cmd],
        &Config::default(),
    );
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.total_freed, 4096);
    let reasons: Vec<_> = plan
        .skipped
        .iter()
        .map(|(id, r)| (id.0.as_str(), r.as_str()))
        .collect();
    assert_eq!(
        reasons,
        [
            ("gone", "Already gone (rescan to refresh)"),
            ("gone-cmd", "Already gone (rescan to refresh)")
        ]
    );
}

#[test]
fn command_that_leaves_the_finding_path_is_credited_what_it_measurably_freed() {
    use std::os::unix::fs::MetadataExt;
    let (d, paths, bin) = setup();
    let proj = d.path().join("proj");
    let target = proj.join("target");
    for sub in ["sub", "keep"] {
        std::fs::create_dir_all(target.join(sub)).unwrap();
        std::fs::write(target.join(sub).join("f"), vec![1u8; 64 * 1024]).unwrap();
    }
    let blocks = |p: &std::path::Path| std::fs::symlink_metadata(p).unwrap().blocks() * 512;
    let sub_bytes = blocks(&target.join("sub")) + blocks(&target.join("sub/f"));
    let cmd = |script: &str, freed: u64| Finding {
        removal: Removal::Command {
            tool: "sh".into(),
            argv: vec!["sh".into(), "-c".into(), script.into()],
            cwd: Some(proj.clone()),
            install_hint: None,
            freed_note: None,
        },
        freed_if_deleted: freed,
        ..trash_finding(&target)
    };

    // Nothing removed: nothing freed.
    let plan = plan_removal(&[&cmd("true", 1 << 30)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin.clone()), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert_eq!(
        rep.results[0].reason.as_deref(),
        Some("command finished; nothing freed")
    );
    assert_eq!(rep.freed_total, 0);
    assert_eq!(history::read(&paths, 1).unwrap()[0].freed, 0);

    // A purge inside the dir: credited what it removed; the dir stays.
    let plan = plan_removal(&[&cmd("rm -rf target/sub", 1 << 30)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin.clone()), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert!(target.join("keep").exists() && !target.join("sub").exists());
    // The parent dir's own blocks may shrink or not: allow one block of slack.
    let got = rep.freed_total;
    assert!(got.abs_diff(sub_bytes) <= 4096, "{got} vs {sub_bytes}");
    let reason = rep.results[0].reason.as_deref().unwrap();
    assert!(
        reason.starts_with("command finished; ")
            && reason.ends_with(&format!(" freed inside {}", target.display())),
        "{reason}"
    );
    assert_eq!(history::read(&paths, 1).unwrap()[0].freed, got);

    // Capped at the planned freed.
    std::fs::create_dir_all(target.join("sub")).unwrap();
    std::fs::write(target.join("sub/f"), vec![1u8; 64 * 1024]).unwrap();
    let plan = plan_removal(&[&cmd("rm -rf target/sub", 10)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin.clone()), &paths).unwrap();
    assert_eq!(rep.freed_total, 10);

    // The same kind of command that removes the path (the cwd stays) is credited in full.
    let plan = plan_removal(&[&cmd("rm -rf target", 4096)], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert_eq!(rep.results[0].reason, None);
    assert_eq!(rep.freed_total, 4096);
}

#[test]
fn only_steps_outside_the_plan_is_an_error_before_anything_runs() {
    let (d, paths, bin) = setup();
    let a = d.path().join("a");
    std::fs::create_dir(&a).unwrap();
    let plan = plan_removal(&[&trash_finding(&a)], &Config::default());
    let mut o = opts(Actor::App, bin);
    o.only_steps = Some(vec![0, 5]);
    let e = execute_plan(&plan, &o, &paths).unwrap_err();
    assert!(matches!(e, ExecuteError::BadStepIndex(5)), "{e}");
    assert!(a.exists());
    assert!(!paths.log.exists());
}

/// A one-shot HTTP server answering every request with `status`; returns its base URL.
fn http_once(status: &'static str) -> String {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let (mut c, _) = l.accept().unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 1024];
        // Headers, then the declared body.
        while let Ok(n) = c.read(&mut buf) {
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req).to_lowercase();
            if let Some(end) = text.find("\r\n\r\n") {
                let len = text
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if req.len() >= end + 4 + len {
                    break;
                }
            }
        }
        let body = r#"{"error":"model not found"}"#;
        let _ = write!(
            c,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    });
    url
}

#[test]
fn ollama_404_is_done_already_absent_and_frees_nothing() {
    let (_d, paths, bin) = setup();
    let f = Finding {
        removal: Removal::OllamaDelete {
            model: "gone:1b".into(),
        },
        path: None,
        ..trash_finding(std::path::Path::new("/unused"))
    };
    let mut plan = plan_removal(&[&f], &Config::default());
    let url = http_once("404 Not Found");
    if let discky_core::plan::StepKind::OllamaDelete { url: u, .. } = &mut plan.steps[0].kind {
        *u = url;
    }
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done), "{rep:?}");
    assert_eq!(rep.results[0].reason.as_deref(), Some("already absent"));
    assert_eq!(rep.freed_total, 0);
}

#[test]
fn relative_command_cwd_fails() {
    let (d, paths, bin) = setup();
    let f = command_finding(d.path(), "true", Some("relative/dir".into()));
    let plan = plan_removal(&[&f], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Failed));
    assert!(
        rep.results[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("relative")
    );
    let h = history::read(&paths, 1).unwrap();
    assert!(h[0].reason.as_deref().unwrap().contains("relative"));
}

#[test]
fn stale_interactive_step_that_will_be_skipped_does_not_block() {
    let (d, paths, bin) = setup();
    std::fs::create_dir(d.path().join("x")).unwrap();
    let mut plan = plan_removal(&[&trash_finding(&d.path().join("x"))], &Config::default());
    // Pretend the step needs admin and its target changed since planning.
    plan.steps[0].flags |= discky_core::plan::StepFlags::INTERACTIVE;
    plan.steps[0].fingerprints[0].mtime = 1;
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Skipped));
}

#[test]
fn interactive_command_is_skipped_without_permission() {
    let (d, paths, bin) = setup();
    let marker = d.path().join("ran");
    let f = command_finding(d.path(), &format!("touch '{}'", marker.display()), None);
    let mut plan = plan_removal(&[&f], &Config::default());
    // An admin command (e.g. `pkgutil --forget`) is planned as an interactive step.
    plan.steps[0].flags |= discky_core::plan::StepFlags::INTERACTIVE;
    let rep = execute_plan(&plan, &opts(Actor::Mcp, bin), &paths).unwrap();
    assert!(!marker.exists());
    assert!(matches!(rep.results[0].status, StepStatus::Skipped));
    assert_eq!(
        rep.results[0].reason.as_deref(),
        Some("Needs an interactive session; run from Discky.app")
    );
    assert_eq!(rep.stopped_at, None);
    assert_eq!(rep.freed_total, 0);
}

#[test]
fn command_env_reaches_the_child() {
    let (d, paths, bin) = setup();
    let marker = d.path().join("ran");
    let f = command_finding(
        d.path(),
        &format!("test \"$DISCKY_T\" = yes && touch '{}'", marker.display()),
        None,
    );
    let mut plan = plan_removal(&[&f], &Config::default());
    let discky_core::plan::StepKind::Command { env, .. } = &mut plan.steps[0].kind else {
        panic!("not a command");
    };
    env.push(("DISCKY_T".into(), "yes".into()));
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done), "{rep:?}");
    assert!(marker.exists());
}

#[test]
fn skipped_quit_skips_the_findings_remaining_steps() {
    let (d, paths, bin) = setup();
    let live = d.path().join("com.example.live");
    std::fs::create_dir(&live).unwrap();
    std::fs::write(live.join("data"), b"x").unwrap();
    let other = d.path().join("other-cache");
    std::fs::create_dir(&other).unwrap();
    let mut running = trash_finding(&live);
    running.flags.push("app-running".into());
    let mut idle = trash_finding(&other);
    idle.id = FindingId("f2".into());
    let plan = plan_removal(&[&running, &idle], &Config::default());
    assert_eq!(plan.steps.len(), 3, "{:#?}", plan.steps);
    assert!(matches!(
        plan.steps[0].kind,
        discky_core::plan::StepKind::Quit { .. }
    ));

    let report = execute_plan(&plan, &opts(Actor::Mcp, bin), &paths).unwrap();
    let by_finding = |id: &str| {
        plan.steps
            .iter()
            .filter(|s| s.finding.0 == id)
            .map(|s| &report.results[s.index])
            .collect::<Vec<_>>()
    };
    let live_results = by_finding("f1");
    assert_eq!(live_results.len(), 2);
    assert_eq!(live_results[0].status, StepStatus::Skipped);
    assert_eq!(live_results[1].status, StepStatus::Skipped);
    assert_eq!(
        live_results[1].reason.as_deref(),
        Some("Needs the app quit first; run from Discky.app")
    );
    assert!(live.exists(), "the running app's files are never touched");
    // Another finding's steps still run.
    assert_eq!(by_finding("f2")[0].status, StepStatus::Done);
    assert!(!other.exists());
    assert_eq!(report.stopped_at, None);
}

#[test]
fn gui_only_command_runs_as_the_user_only_when_interactive_is_allowed() {
    let (d, paths, bin) = setup();
    let marker = d.path().join("ran");
    let f = command_finding(d.path(), &format!("touch '{}'", marker.display()), None);
    let mut plan = plan_removal(&[&f], &Config::default());
    plan.steps[0].flags |= discky_core::plan::StepFlags::GUI_ONLY;
    let rep = execute_plan(&plan, &opts(Actor::Mcp, bin.clone()), &paths).unwrap();
    assert!(!marker.exists());
    assert_eq!(rep.results[0].status, StepStatus::Skipped);
    assert_eq!(
        rep.results[0].reason.as_deref(),
        Some("Needs an interactive session; run from Discky.app")
    );
    // Allowed: a plain child process as us (the admin route would prompt via osascript).
    let mut allowed = opts(Actor::App, bin);
    allowed.allow_interactive = true;
    let rep = execute_plan(&plan, &allowed, &paths).unwrap();
    assert_eq!(
        rep.results[0].status,
        StepStatus::Done,
        "{:?}",
        rep.results[0]
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&marker).unwrap().uid(), unsafe {
        libc::getuid()
    });
}

#[test]
fn skipped_script_skips_the_findings_remaining_steps() {
    use discky_core::findings::{AppSource, Component, ComponentKind, ComponentRemoval};
    use discky_core::plan::{PlanItem, PlanTools, StepFlags, plan_items_with_tools};
    let (d, paths, bin) = setup();
    let bundle = d.path().join("Foo.app");
    std::fs::create_dir(&bundle).unwrap();
    let script = d.path().join("uninstall.sh");
    let marker = d.path().join("script-ran");
    std::fs::write(&script, format!("touch '{}'\n", marker.display())).unwrap();
    let comp = |kind, path: &std::path::Path, removal| Component {
        title: "x".into(),
        kind,
        path: Some(path.into()),
        allocated: 1,
        freed_if_deleted: 1,
        modified: None,
        default_on: true,
        removal,
        note: None,
        covered_by_cask: false,
    };
    let f = Finding {
        id: FindingId("app".into()),
        category: Category::Apps,
        removal: Removal::App {
            source: AppSource::Dragged,
            bundle: bundle.clone(),
            bundle_id: Some("com.example.foo".into()),
        },
        components: vec![
            comp(ComponentKind::AppBundle, &bundle, ComponentRemoval::Trash),
            comp(
                ComponentKind::OwnUninstaller,
                &script,
                ComponentRemoval::RunScript,
            ),
        ],
        ..trash_finding(&bundle)
    };
    let items = [PlanItem {
        id: "app".into(),
        components: Some(vec![0, 1]),
    }];
    let plan = plan_items_with_tools(&items, &[&f], &Config::default(), &PlanTools::default());
    assert_eq!(plan.steps.len(), 2, "{:#?}", plan.steps);
    assert!(plan.steps[0].flags.contains(StepFlags::GATE));

    // MCP: the script is skipped, so the bundle stays.
    let rep = execute_plan(&plan, &opts(Actor::Mcp, bin.clone()), &paths).unwrap();
    assert_eq!(rep.results[0].status, StepStatus::Skipped);
    assert_eq!(rep.results[1].status, StepStatus::Skipped);
    assert_eq!(
        rep.results[1].reason.as_deref(),
        Some("Needs an earlier interactive step; run from Discky.app")
    );
    assert!(bundle.exists() && !marker.exists());

    // Left out of `only_steps`: the same.
    let mut only = opts(Actor::Mcp, bin);
    only.allow_interactive = true;
    only.only_steps = Some(vec![1]);
    let rep = execute_plan(&plan, &only, &paths).unwrap();
    assert_eq!(rep.results[1].status, StepStatus::Skipped);
    assert!(bundle.exists() && !marker.exists());
}
