use discky_core::{
    config::{Config, RemovalMode},
    findings::{Finding, FindingId, Removal},
    plan::{StepFlags, StepKind, plan_removal},
    rules::{Category, SafetyLabel},
};

fn finding(id: &str, removal: Removal, freed: u64, label: SafetyLabel) -> Finding {
    Finding {
        id: FindingId(id.into()),
        category: Category::DevCaches,
        title: id.into(),
        subtitle: None,
        path: Some(std::env::temp_dir().join(id)),
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
    let mut f2 = finding(
        "sys",
        Removal::Trash {
            paths: vec!["/Library/Logs/X".into()],
        },
        1,
        SafetyLabel::AppData,
    );
    f2.path = Some("/Library/Logs/X".into());
    let plan = plan_removal(&[&f1, &f2], &Config::default());
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0].1, "Marked do-not-touch");
    assert!(plan.steps[0].flags.contains(StepFlags::INTERACTIVE));
    assert!(!plan.steps[0].fingerprints[0].exists);
    assert_eq!(plan.steps[0].fingerprints[0].allocated, 0);
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
            paths: vec![std::env::temp_dir().join("t1")],
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
    let app_dir = std::env::temp_dir().join("com.example.app");
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
    let p = std::env::temp_dir().join("discky-plan-json");
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
