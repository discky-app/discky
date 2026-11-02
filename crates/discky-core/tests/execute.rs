use discky_core::{
    DisckyPaths,
    config::Config,
    findings::{Finding, FindingId, Removal},
    history,
    index::snapshot::Actor,
    plan::{
        execute::{ExecuteError, ExecuteOptions, StepStatus, execute_plan},
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
    }
}

fn opts(actor: Actor, bin: std::path::PathBuf) -> ExecuteOptions {
    ExecuteOptions {
        allow_interactive: false,
        only_steps: None,
        actor,
        trash_bin: bin,
    }
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
fn interactive_steps_are_skipped_without_permission() {
    let (d, paths, bin) = setup();
    let mut f = trash_finding(&d.path().join("x"));
    std::fs::create_dir(d.path().join("x")).unwrap();
    f.path = Some("/Library/Logs/Discky-test".into());
    f.removal = Removal::Trash {
        paths: vec!["/Library/Logs/Discky-test".into()],
    };
    let plan = plan_removal(&[&f], &Config::default());
    let rep = execute_plan(&plan, &opts(Actor::Mcp, bin), &paths).unwrap();
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

#[test]
fn trash_of_an_already_missing_path_is_done_without_invoking_trash() {
    let (d, paths, bin) = setup();
    let missing = d.path().join("gone-before-planning");
    let plan = plan_removal(&[&trash_finding(&missing)], &Config::default());
    assert!(!plan.steps[0].fingerprints[0].exists);
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert_eq!(rep.results[0].reason.as_deref(), Some("already absent"));
    assert_eq!(rep.results[0].freed, 4096);
    assert_eq!(
        std::fs::read_dir(d.path().join("trashed")).unwrap().count(),
        0
    );
    let h = history::read(&paths, 1).unwrap();
    assert_eq!(h[0].reason.as_deref(), Some("already absent"));
    assert!(h[0].trash_paths.is_empty());
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
    let mut plan = plan_removal(&[&trash_finding(&d.path().join("x"))], &Config::default());
    // Pretend the step needs admin and its target changed since planning.
    plan.steps[0].flags |= discky_core::plan::StepFlags::INTERACTIVE;
    plan.steps[0].fingerprints[0].mtime = 1;
    let rep = execute_plan(&plan, &opts(Actor::App, bin), &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Skipped));
}
