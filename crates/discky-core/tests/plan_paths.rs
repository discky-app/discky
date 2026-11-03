use std::fs;
use std::path::{Path, PathBuf};

use discky_core::{
    Config, RemovalMode,
    findings::{Finding, FindingId, Removal},
    fs::walk::{ScanOptions, walk},
    index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotMeta},
    plan::{
        NOT_IN_SNAPSHOT, PATH_ID_PREFIX, PROTECTED_REFUSED, ROOT_REFUSED, StepFlags, StepKind,
        is_protected, managed_by, plan_paths_in,
    },
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

fn finding(s: &Snapshot, category: Category, path: &Path, removal: Removal) -> Finding {
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
        removal,
        flags: vec![],
        components: vec![],
    }
}

fn skipped_reason(plan: &discky_core::plan::Plan, p: &Path) -> String {
    let id = format!("{PATH_ID_PREFIX}{}", p.display());
    plan.skipped
        .iter()
        .find(|(i, _)| i.0 == id)
        .unwrap_or_else(|| panic!("{id} not skipped: {:?}", plan.skipped))
        .1
        .clone()
}

#[test]
fn plans_one_trash_step_per_existing_path() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a/one.bin"), d.path().join("b/two.bin"));
    touch(&a, 100);
    touch(&b, 5000);
    let s = snap(d.path());
    let plan = plan_paths_in(
        &[a.clone(), b.clone(), a.clone()],
        &s,
        &Config::default(),
        d.path(),
    );
    assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
    assert_eq!(plan.steps.len(), 2);
    for (step, p) in plan.steps.iter().zip([&a, &b]) {
        assert_eq!(step.finding.0, format!("{PATH_ID_PREFIX}{}", p.display()));
        assert!(
            matches!(&step.kind, StepKind::Trash { paths } if paths == std::slice::from_ref(p))
        );
        assert_eq!(step.fingerprints.len(), 1);
    }
    let want: u64 = [&a, &b]
        .iter()
        .map(|p| s.index.node(s.index.find(p).unwrap()).private)
        .sum();
    assert!(want > 0);
    assert_eq!(plan.total_freed, want);
    assert_eq!(plan.steps[1].index, 1);
}

#[test]
fn permanent_mode_plans_remove_steps() {
    let d = tempfile::tempdir().unwrap();
    let a = d.path().join("a/one.bin");
    touch(&a, 100);
    let s = snap(d.path());
    let mut cfg = Config::default();
    cfg.removal.mode = RemovalMode::Permanent;
    let plan = plan_paths_in(&[a], &s, &cfg, d.path());
    assert_eq!(plan.steps.len(), 1);
    assert!(matches!(plan.steps[0].kind, StepKind::Remove { .. }));
    assert!(plan.steps[0].flags.contains(StepFlags::PERMANENT));
}

#[test]
fn refuses_roots_and_protected_locations() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    let lib = h.join("Library");
    let kc = lib.join("Keychains/login.keychain-db");
    let md = lib.join("Mobile Documents/x");
    touch(&kc, 10);
    touch(&md, 10);
    let s = snap(h);
    let plan = plan_paths_in(
        &[h.into(), lib.clone(), kc.clone(), md.clone()],
        &s,
        &Config::default(),
        h,
    );
    assert!(plan.steps.is_empty());
    assert_eq!(skipped_reason(&plan, h), ROOT_REFUSED);
    for p in [&lib, &kc, &md] {
        assert_eq!(skipped_reason(&plan, p), PROTECTED_REFUSED);
    }
}

#[test]
fn refuses_paths_inside_command_managed_findings() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join(".cargo/registry");
    let inner = root.join("cache/x");
    touch(&inner, 10);
    let mut s = snap(d.path());
    let f = finding(
        &s,
        Category::DevCaches,
        &root,
        Removal::Command {
            tool: "tool".into(),
            argv: vec!["tool".into(), "clean".into()],
            cwd: None,
            install_hint: None,
            freed_note: None,
        },
    );
    s.findings.push(f);
    let plan = plan_paths_in(
        std::slice::from_ref(&inner),
        &s,
        &Config::default(),
        d.path(),
    );
    assert!(plan.steps.is_empty());
    assert_eq!(
        skipped_reason(&plan, &inner),
        managed_by(Category::DevCaches)
    );
}

#[test]
fn allows_paths_inside_trash_managed_findings() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("proj/target");
    let inner = root.join("debug");
    touch(&inner.join("f"), 10);
    let mut s = snap(d.path());
    let f = finding(
        &s,
        Category::ProjectBuilds,
        &root,
        Removal::Trash {
            paths: vec![root.clone()],
        },
    );
    s.findings.push(f);
    let plan = plan_paths_in(&[inner], &s, &Config::default(), d.path());
    assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
    assert_eq!(plan.steps.len(), 1);
}

#[test]
fn unknown_and_relative_paths_are_not_in_snapshot() {
    let d = tempfile::tempdir().unwrap();
    touch(&d.path().join("a"), 1);
    let s = snap(d.path());
    let rel = PathBuf::from("relative/x");
    let nope = d.path().join("nope");
    let plan = plan_paths_in(
        &[rel.clone(), nope.clone()],
        &s,
        &Config::default(),
        d.path(),
    );
    assert!(plan.steps.is_empty());
    assert_eq!(skipped_reason(&plan, &rel), NOT_IN_SNAPSHOT);
    assert_eq!(skipped_reason(&plan, &nope), NOT_IN_SNAPSHOT);
}

#[test]
fn is_protected_matches_exact_and_descendants_only() {
    let h = Path::new("/h/user");
    assert!(is_protected(&h.join("Library"), h));
    assert!(!is_protected(&h.join("LibraryX"), h));
    assert!(!is_protected(&h.join("Library/Caches"), h));
    assert!(is_protected(&h.join("Library/Preferences/a.plist"), h));
    assert!(is_protected(&h.join("Library/CloudStorage"), h));
    assert!(is_protected(Path::new("/System/Library"), h));
    assert!(is_protected(Path::new("/Library/Keychains/x"), h));
    assert!(!is_protected(Path::new("/Library/Caches"), h));
}
