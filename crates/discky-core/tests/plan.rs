use discky_core::{
    config::{Config, RemovalMode},
    findings::{
        AppSource, Component, ComponentKind, ComponentRemoval, Finding, FindingId, Removal,
    },
    plan::{
        Plan, PlanId, PlanItem, Step, StepFlags, StepKind, needs_admin, plan_items, plan_removal,
    },
    rules::{Category, SafetyLabel},
};

/// `<tmp>/discky-plan-<name>`, created: planning skips findings whose paths are all gone.
fn existing(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("discky-plan-{name}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A finding whose own path exists.
fn finding(id: &str, removal: Removal, freed: u64, label: SafetyLabel) -> Finding {
    Finding {
        id: FindingId(id.into()),
        category: Category::DevCaches,
        title: id.into(),
        subtitle: None,
        path: Some(existing(id)),
        node: None,
        allocated: freed,
        logical: freed,
        freed_if_deleted: freed,
        modified: None,
        label,
        rule_id: "t".into(),
        explain: String::new(),
        removal,
        flags: vec![],
        components: Vec::new(),
    }
}

#[test]
fn trash_mode_makes_trash_steps_and_permanent_mode_flags_them() {
    let p = std::env::temp_dir().join("discky-plan-a");
    std::fs::create_dir_all(&p).unwrap();
    let f = finding(
        "discky-plan-a",
        Removal::Trash {
            paths: vec![p.clone()],
        },
        10,
        SafetyLabel::Regenerates,
    );
    let mut cfg = Config::default();
    let plan = plan_removal(&[&f], &cfg);
    assert!(matches!(plan.steps[0].kind, StepKind::Trash { .. }));
    assert_eq!(plan.total_freed, 10);
    assert_eq!(plan.steps[0].fingerprints[0].path, p);
    assert!(plan.steps[0].fingerprints[0].exists);
    // The temp dir is writable by us, so no admin prompt is needed.
    assert!(!plan.steps[0].flags.contains(StepFlags::INTERACTIVE));
    cfg.removal.mode = RemovalMode::Permanent;
    let plan = plan_removal(&[&f], &cfg);
    assert!(matches!(plan.steps[0].kind, StepKind::Remove { .. }));
    assert!(plan.steps[0].flags.contains(StepFlags::PERMANENT));
}

#[test]
fn missing_tool_is_flagged_with_hint_and_note_suppresses_freed() {
    let f = finding(
        "x",
        Removal::Command {
            tool: "definitely-not-a-tool".into(),
            argv: vec!["definitely-not-a-tool".into(), "clean".into()],
            cwd: None,
            install_hint: Some("brew install nothing".into()),
            freed_note: Some("Frees space inside the VM".into()),
        },
        5_000,
        SafetyLabel::AppData,
    );
    let plan = plan_removal(&[&f], &Config::default());
    let s = &plan.steps[0];
    assert!(s.flags.contains(StepFlags::TOOL_MISSING));
    assert!(s.warnings[0].contains("brew install nothing"));
    assert_eq!(s.freed, None);
    assert_eq!(s.freed_note.as_deref(), Some("Frees space inside the VM"));
    assert_eq!(plan.total_freed, 0);
}

#[test]
fn command_without_note_credits_freed_and_finds_installed_tool() {
    let f = finding(
        "sh",
        Removal::Command {
            tool: "sh".into(),
            argv: vec!["sh".into(), "-c".into(), "true".into()],
            cwd: Some(std::env::temp_dir()),
            install_hint: None,
            freed_note: None,
        },
        7,
        SafetyLabel::Regenerates,
    );
    let plan = plan_removal(&[&f], &Config::default());
    let s = &plan.steps[0];
    assert!(!s.flags.contains(StepFlags::TOOL_MISSING));
    assert!(s.warnings.is_empty());
    assert_eq!(s.freed, Some(7));
    assert_eq!(s.fingerprints.len(), 2);
    assert_eq!(plan.total_freed, 7);
}

#[test]
fn do_not_touch_is_skipped_and_outside_home_is_interactive() {
    let f1 = finding("k", Removal::None, 1, SafetyLabel::DoNotTouch);
    // Planned only, never run: a root-owned dir that exists on every Mac.
    let mut f2 = finding(
        "sys",
        Removal::Trash {
            paths: vec!["/Library/Logs".into()],
        },
        1,
        SafetyLabel::AppData,
    );
    f2.path = Some("/Library/Logs".into());
    let plan = plan_removal(&[&f1, &f2], &Config::default());
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].1, "Marked do-not-touch");
    assert!(plan.steps[0].flags.contains(StepFlags::INTERACTIVE));
    assert!(plan.steps[0].fingerprints[0].exists);
}

#[test]
fn ollama_and_quit_ordering() {
    let f = finding(
        "m",
        Removal::OllamaDelete {
            model: "qwen3:4b".into(),
        },
        2,
        SafetyLabel::AppData,
    );
    let plan = plan_removal(&[&f], &Config::default());
    assert!(
        matches!(&plan.steps[0].kind, StepKind::OllamaDelete { model, .. } if model == "qwen3:4b")
    );
    assert!(plan.steps[0].fingerprints.is_empty());
    assert_eq!(plan.steps[0].freed, Some(2));
}

#[test]
fn steps_are_ordered_quit_then_commands_then_trash() {
    let trash = finding(
        "t1",
        Removal::Trash {
            paths: vec![existing("t1")],
        },
        1,
        SafetyLabel::Regenerates,
    );
    let ollama = finding(
        "o1",
        Removal::OllamaDelete { model: "a".into() },
        2,
        SafetyLabel::AppData,
    );
    let app_dir = existing("x").join("com.example.app");
    std::fs::create_dir_all(&app_dir).unwrap();
    let mut app = finding(
        "a1",
        Removal::Trash {
            paths: vec![app_dir.clone()],
        },
        3,
        SafetyLabel::AppData,
    );
    app.flags = vec!["app-running".into()];
    app.path = Some(app_dir);
    app.title = "Example".into();
    let plan = plan_removal(&[&trash, &ollama, &app], &Config::default());
    let kinds: Vec<&str> = plan
        .steps
        .iter()
        .map(|s| match s.kind {
            StepKind::Quit { .. } => "quit",
            StepKind::Command { .. } | StepKind::OllamaDelete { .. } => "cmd",
            StepKind::Trash { .. } | StepKind::Remove { .. } => "trash",
        })
        .collect();
    assert_eq!(kinds, ["quit", "cmd", "trash", "trash"]);
    assert!(
        matches!(&plan.steps[0].kind, StepKind::Quit { bundle_id } if bundle_id == "com.example.app")
    );
    assert_eq!(plan.steps[0].description, "Quit Example (com.example.app)");
    assert!(plan.steps[0].flags.contains(StepFlags::INTERACTIVE));
    assert_eq!(plan.steps[0].freed, None);
    assert_eq!(plan.steps[2].finding.0, "t1");
    assert_eq!(plan.steps[3].finding.0, "a1");
    let idx: Vec<usize> = plan.steps.iter().map(|s| s.index).collect();
    assert_eq!(idx, [0, 1, 2, 3]);
    assert_eq!(plan.total_freed, 6);
}

#[test]
fn to_json_has_the_documented_shape() {
    let p = existing("json");
    let f = finding(
        "discky-plan-json",
        Removal::Trash {
            paths: vec![p.clone()],
        },
        4,
        SafetyLabel::Regenerates,
    );
    let skip = finding("k", Removal::None, 1, SafetyLabel::DoNotTouch);
    let mut cfg = Config::default();
    cfg.removal.mode = RemovalMode::Permanent;
    let plan = plan_removal(&[&f, &skip], &cfg);
    assert_eq!(plan.id.0.len(), 16);
    let j = plan.to_json();
    assert_eq!(j["id"], plan.id.0.as_str());
    assert_eq!(j["created_at"], plan.created_at);
    assert_eq!(j["total_freed"], 4);
    let s = &j["steps"][0];
    assert_eq!(s["index"], 0);
    assert_eq!(s["finding"], "discky-plan-json");
    assert_eq!(s["kind"], "remove");
    assert_eq!(s["paths"][0], p.to_string_lossy().as_ref());
    assert_eq!(s["freed"], 4);
    assert!(s["freed_note"].is_null());
    assert_eq!(s["flags"], serde_json::json!(["permanent"]));
    assert!(s["warnings"].as_array().unwrap().is_empty());
    assert!(s["description"].as_str().unwrap().starts_with("Delete "));
    assert_eq!(j["skipped"][0]["finding"], "k");
    assert_eq!(j["skipped"][0]["reason"], "Marked do-not-touch");
    // Round-trips through serde.
    let back: discky_core::plan::Plan =
        serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
    assert_eq!(back.steps[0].flags, plan.steps[0].flags);
}

#[test]
fn symlinked_ancestor_is_resolved_for_the_admin_check() {
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink("/Library/Logs", &link).unwrap();
    // Checked directly: planning skips findings whose paths do not exist.
    assert!(needs_admin(&link.join("X")));

    // A dangling link is skipped: the next ancestor (our temp dir) decides.
    let dangling = tmp.path().join("dangling");
    std::os::unix::fs::symlink(tmp.path().join("missing"), &dangling).unwrap();
    assert!(!needs_admin(&dangling.join("X")));
}

#[test]
fn cargo_cache_is_checked_by_tool_while_argv_runs_cargo() {
    let f = finding(
        "cc",
        Removal::Command {
            tool: "cargo-cache".into(),
            argv: vec!["cargo".into(), "cache".into(), "--autoclean".into()],
            cwd: None,
            install_hint: Some("cargo install cargo-cache".into()),
            freed_note: None,
        },
        3,
        SafetyLabel::Regenerates,
    );
    let installed = std::process::Command::new("cargo")
        .args(["cache", "--version"])
        .output()
        .is_ok_and(|o| o.status.success());
    let plan = plan_removal(&[&f], &Config::default());
    let s = &plan.steps[0];
    if installed {
        assert!(!s.flags.contains(StepFlags::TOOL_MISSING));
        assert!(s.warnings.is_empty());
    } else {
        assert!(s.flags.contains(StepFlags::TOOL_MISSING));
        assert_eq!(
            s.warnings,
            ["cargo-cache not found. cargo install cargo-cache"]
        );
    }
    // argv[0] is resolved on its own (to cargo), whatever the tool name.
    let StepKind::Command { argv, .. } = &s.kind else {
        panic!("not a command step");
    };
    assert!(argv[0].ends_with("/cargo"), "{argv:?}");
    assert_eq!(s.description, "Run `cargo cache --autoclean`");
}

#[test]
fn to_json_survives_non_utf8_paths() {
    use std::os::unix::ffi::OsStrExt;
    let p = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe"));
    let plan = Plan {
        id: PlanId("p".into()),
        created_at: 0,
        steps: vec![Step {
            index: 0,
            finding: FindingId("f".into()),
            description: "Move it to the Trash".into(),
            kind: StepKind::Trash { paths: vec![p] },
            freed: Some(1),
            freed_note: None,
            flags: StepFlags::empty(),
            warnings: vec![],
            fingerprints: vec![],
            component: None,
        }],
        total_freed: 1,
        skipped: vec![],
    };
    let v = plan.to_json();
    assert_eq!(v["steps"][0]["kind"], "trash");
    let shown = v["steps"][0]["paths"][0].as_str().unwrap();
    assert!(shown.contains('\u{FFFD}'), "{shown}");
}

/// A `Trash` component at `path`.
fn component(
    kind: ComponentKind,
    path: std::path::PathBuf,
    freed: u64,
    default_on: bool,
) -> Component {
    Component {
        kind,
        title: path.file_name().unwrap().to_string_lossy().into_owned(),
        path: Some(path),
        allocated: freed,
        freed_if_deleted: freed,
        modified: None,
        default_on,
        removal: ComponentRemoval::Trash,
        note: None,
        covered_by_cask: false,
    }
}

/// An app finding: bundle component (default on) and a caches component (default off).
fn app_finding(name: &str) -> Finding {
    let bundle = existing(&format!("{name}.app"));
    let caches = existing(&format!("{name}-caches"));
    let mut f = finding(
        name,
        Removal::App {
            source: AppSource::Dragged,
            bundle: bundle.clone(),
            bundle_id: Some(format!("com.example.{name}")),
        },
        100,
        SafetyLabel::AppData,
    );
    f.path = Some(bundle.clone());
    f.components = vec![
        component(ComponentKind::AppBundle, bundle, 100, true),
        component(ComponentKind::Caches, caches, 30, false),
    ];
    f
}

#[test]
fn plan_items_with_no_selection_uses_default_on_components() {
    let f = app_finding("defaults");
    let items = [PlanItem {
        id: f.id.0.clone(),
        components: None,
    }];
    let plan = plan_items(&items, &[&f], &Config::default());
    assert_eq!(plan.steps.len(), 1, "{:?}", plan.steps);
    assert!(
        matches!(&plan.steps[0].kind, StepKind::Trash { paths } if paths[0].ends_with("discky-plan-defaults.app"))
    );
    assert_eq!(plan.steps[0].component, Some(0));
    assert_eq!(plan.total_freed, 100);
    assert!(plan.skipped.is_empty());

    // Selecting both components trashes the leftovers too.
    let items = [PlanItem {
        id: f.id.0.clone(),
        components: Some(vec![0, 1]),
    }];
    let plan = plan_items(&items, &[&f], &Config::default());
    let comps: Vec<Option<usize>> = plan.steps.iter().map(|s| s.component).collect();
    assert_eq!(comps, [Some(0), Some(1)]);
    assert_eq!(plan.total_freed, 130);
    let j = plan.to_json();
    assert_eq!(j["steps"][1]["component"], 1);
}

#[test]
fn plan_items_rejects_bad_component_index() {
    let f = app_finding("badidx");
    let items = [PlanItem {
        id: f.id.0.clone(),
        components: Some(vec![0, 7]),
    }];
    let plan = plan_items(&items, &[&f], &Config::default());
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].0, f.id);
    assert!(
        plan.skipped[0].1.contains("Unknown component index 7"),
        "{:?}",
        plan.skipped
    );

    // A finding without components cannot take a component selection.
    let plain = finding(
        "plain",
        Removal::Trash {
            paths: vec![existing("plain")],
        },
        1,
        SafetyLabel::Regenerates,
    );
    let items = [PlanItem {
        id: plain.id.0.clone(),
        components: Some(vec![0]),
    }];
    let plan = plan_items(&items, &[&plain], &Config::default());
    assert!(plan.steps.is_empty());
    assert_eq!(plan.skipped[0].1, "Finding has no components");
}

#[test]
fn mise_uninstall_plans_a_mise_command() {
    let f = finding(
        "mise-node",
        Removal::MiseUninstall {
            tool: "node".into(),
            version: "20.1.0".into(),
        },
        9,
        SafetyLabel::AppData,
    );
    let plan = plan_removal(&[&f], &Config::default());
    let s = &plan.steps[0];
    let StepKind::Command { argv, cwd } = &s.kind else {
        panic!("not a command step");
    };
    assert!(argv[0] == "mise" || argv[0].ends_with("/mise"), "{argv:?}");
    assert_eq!(&argv[1..], ["uninstall", "node@20.1.0"]);
    assert_eq!(*cwd, None);
    assert_eq!(s.component, None);
    assert_eq!(
        s.flags.contains(StepFlags::TOOL_MISSING),
        discky_core::tools::tool_path("mise").is_none()
    );
    assert!(plan.to_json()["steps"][0]["component"].is_null());
}
