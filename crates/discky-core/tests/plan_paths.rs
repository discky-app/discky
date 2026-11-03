use std::fs;
use std::path::{Path, PathBuf};

use discky_core::{
    Config, RemovalMode,
    findings::{Finding, FindingId, Removal},
    fs::walk::{ScanOptions, walk},
    index::NodeFlags,
    index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotMeta},
    plan::{
        CLOUD_REFUSED, NOT_IN_SNAPSHOT, PATH_ID_PREFIX, PROTECTED_REFUSED, ROOT_REFUSED, StepFlags,
        StepKind, is_protected, managed_by, plan_paths_in,
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

#[test]
fn unknown_home_protects_everything() {
    let d = tempfile::tempdir().unwrap();
    let a = d.path().join("a");
    touch(&a, 10);
    let s = snap(d.path());
    for home in [Path::new(""), Path::new("rel")] {
        assert!(is_protected(&a, home));
        let plan = plan_paths_in(std::slice::from_ref(&a), &s, &Config::default(), home);
        assert!(plan.steps.is_empty());
        assert_eq!(skipped_reason(&plan, &a), PROTECTED_REFUSED);
    }
}

/// Snapshot of `root` with `flag` set on the node of every path in `marked`.
fn snap_flagged(root: &Path, marked: &[&Path], flag: NodeFlags) -> Snapshot {
    let mut s = snap(root);
    let ids: Vec<_> = marked.iter().map(|p| s.index.find(p).unwrap()).collect();
    let index = std::sync::Arc::get_mut(&mut s.index).unwrap();
    for id in ids {
        index.nodes[id.0 as usize].flags |= flag;
    }
    s
}

#[test]
fn dataless_is_refused_and_beats_protected() {
    let d = tempfile::tempdir().unwrap();
    let cloud = d.path().join("docs/big.bin");
    let kc = d.path().join("Library/Keychains/k");
    touch(&cloud, 10);
    touch(&kc, 10);
    let s = snap_flagged(d.path(), &[&cloud, &kc], NodeFlags::DATALESS);
    let plan = plan_paths_in(
        &[cloud.clone(), kc.clone()],
        &s,
        &Config::default(),
        d.path(),
    );
    assert!(plan.steps.is_empty());
    assert_eq!(skipped_reason(&plan, &cloud), CLOUD_REFUSED);
    assert_eq!(skipped_reason(&plan, &kc), CLOUD_REFUSED);
}

#[test]
fn root_beats_protected() {
    let d = tempfile::tempdir().unwrap();
    let lib = d.path().join("Library");
    touch(&lib.join("x"), 10);
    let s = snap(&lib);
    let plan = plan_paths_in(std::slice::from_ref(&lib), &s, &Config::default(), d.path());
    assert_eq!(skipped_reason(&plan, &lib), ROOT_REFUSED);
}

#[test]
fn protected_beats_managed() {
    let d = tempfile::tempdir().unwrap();
    let lib = d.path().join("Library");
    let inner = lib.join("Keychains/k");
    touch(&inner, 10);
    let mut s = snap(d.path());
    let f = finding(&s, Category::DevCaches, &lib, command());
    s.findings.push(f);
    let plan = plan_paths_in(
        std::slice::from_ref(&inner),
        &s,
        &Config::default(),
        d.path(),
    );
    assert_eq!(skipped_reason(&plan, &inner), PROTECTED_REFUSED);
}

#[test]
fn refuses_ancestors_of_managed_findings() {
    let d = tempfile::tempdir().unwrap();
    let reg = d.path().join(".cargo/registry");
    touch(&reg.join("cache/x"), 10);
    let mut s = snap(d.path());
    let f = finding(&s, Category::DevCaches, &reg, command());
    s.findings.push(f);
    let cargo = d.path().join(".cargo");
    let plan = plan_paths_in(
        std::slice::from_ref(&cargo),
        &s,
        &Config::default(),
        d.path(),
    );
    assert_eq!(
        skipped_reason(&plan, &cargo),
        managed_by(Category::DevCaches)
    );
}

#[test]
fn refuses_ancestors_of_protected_locations() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("Users/me");
    touch(&home.join("Library/Caches/x"), 10);
    touch(&d.path().join("Other/y"), 10);
    let s = snap(d.path());
    let users = d.path().join("Users");
    let other = d.path().join("Other");
    let plan = plan_paths_in(
        &[users.clone(), other.clone()],
        &s,
        &Config::default(),
        &home,
    );
    assert_eq!(skipped_reason(&plan, &users), PROTECTED_REFUSED);
    assert_eq!(plan.steps.len(), 1);
    assert!(matches!(&plan.steps[0].kind, StepKind::Trash { paths } if paths == &[other]));
}

#[test]
fn directory_step_credits_agg_private() {
    let d = tempfile::tempdir().unwrap();
    touch(&d.path().join("dir/a"), 5000);
    touch(&d.path().join("dir/b"), 5000);
    let s = snap(d.path());
    let dir = d.path().join("dir");
    let plan = plan_paths_in(std::slice::from_ref(&dir), &s, &Config::default(), d.path());
    let want = s.index.node(s.index.find(&dir).unwrap()).agg_private;
    assert!(want >= 10000);
    assert_eq!(plan.steps[0].freed, Some(want));
}

#[test]
fn admin_path_step_is_interactive() {
    // The system log dir is root-owned on macOS, so removing a child needs an admin.
    let sys = Path::new("/Library/Logs");
    let Some(child) = fs::read_dir(sys)
        .ok()
        .and_then(|mut it| it.find_map(|e| e.ok()))
        .map(|e| e.path())
    else {
        return;
    };
    let s = snap(sys);
    let home = tempfile::tempdir().unwrap();
    let plan = plan_paths_in(&[child], &s, &Config::default(), home.path());
    assert_eq!(plan.steps.len(), 1, "{:?}", plan.skipped);
    assert!(plan.steps[0].flags.contains(StepFlags::INTERACTIVE));
}

fn command() -> Removal {
    Removal::Command {
        tool: "tool".into(),
        argv: vec!["tool".into(), "clean".into()],
        cwd: None,
        install_hint: None,
        freed_note: None,
    }
}
