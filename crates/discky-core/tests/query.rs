mod fixtures;
use discky_core::{
    config::Thresholds,
    findings::{Categorizer, Finding, FindingId, Removal},
    fs::attr::ObjKind,
    fs::walk::{ScanOptions, walk},
    index::snapshot::{Actor, SNAPSHOT_FORMAT, Snapshot, SnapshotMeta},
    query::{SearchQuery, disk_overview, findings_in, search, tree},
    rules::{Category, RuleSet, SafetyLabel},
};

fn snap(root: &std::path::Path) -> Snapshot {
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
    let findings = Categorizer {
        index: &index,
        rules: &RuleSet::builtin(),
        thresholds: &Thresholds::default(),
    }
    .run_with_home(Some(root));
    Snapshot {
        meta: SnapshotMeta {
            format_version: SNAPSHOT_FORMAT,
            created_at: 1,
            actor: Actor::App,
            roots: vec![root.into()],
            no_access: vec![],
            node_count: 0,
            exact_private_size: false,
        },
        index: index.into(),
        findings,
    }
}

#[test]
fn tree_lists_children_largest_first_with_finding_links() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let s = snap(d.path());
    let t = tree(&s, &d.path().join("proj"), 10).unwrap();
    assert_eq!(t[0].name, "target");
    assert!(t[0].finding.is_some());
    assert!(tree(&s, std::path::Path::new("/definitely/missing"), 10).is_err());
}

#[test]
fn search_by_glob_size_and_kind() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let s = snap(d.path());
    let r = search(
        &s,
        &SearchQuery {
            name_glob: Some("*.bin".into()),
            kind: Some(ObjKind::File),
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "big.bin");
    let r = search(
        &s,
        &SearchQuery {
            name_glob: Some("node_modules".into()),
            min_allocated: Some(1024 * 1024),
            kind: Some(ObjKind::Dir),
            under: Some(d.path().join("web")),
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(r.len(), 1);
    let r = search(
        &s,
        &SearchQuery {
            name_glob: Some("node_modules".into()),
            under: Some(d.path().join("proj")),
            ..Default::default()
        },
    );
    assert!(r.is_empty());
}

#[test]
fn overview_sums_categories_and_safe_bytes() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let s = snap(d.path());
    let o = disk_overview(Some(&s));
    assert!(o.volume.total > 0 && o.volume.used <= o.volume.total);
    assert!(
        o.safe_to_free >= 5 * 1024 * 1024,
        "target + node_modules regenerate"
    );
    assert_eq!(o.by_category.len(), 7);
    assert!(
        o.by_category
            .iter()
            .any(|(c, b)| matches!(c, Category::ProjectBuilds) && *b > 0)
    );
    assert!(disk_overview(None).snapshot_at.is_none());
}

#[test]
fn findings_in_filters_and_pages() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let s = snap(d.path());
    let (all, total) = findings_in(&s, None, None, 0, None, 0, 100);
    assert_eq!(all.len(), total);
    let (page, total2) = findings_in(&s, None, None, 0, None, 1, 1);
    assert_eq!(total2, total);
    assert!(page.len() <= 1);
    let (b, _) = findings_in(
        &s,
        Some(Category::ProjectBuilds),
        Some(SafetyLabel::Regenerates),
        0,
        None,
        0,
        100,
    );
    assert!(!b.is_empty() && b.iter().all(|f| f.category == Category::ProjectBuilds));
}

#[test]
fn search_limit_keeps_the_largest_matches() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("many");
    std::fs::create_dir(&dir).unwrap();
    for i in 0..60 {
        std::fs::write(dir.join(format!("f{i:02}.dat")), vec![1u8; 100]).unwrap();
    }
    std::fs::write(dir.join("largest.dat"), vec![1u8; 1024 * 1024]).unwrap();
    let s = snap(d.path());
    let r = search(
        &s,
        &SearchQuery {
            kind: Some(ObjKind::File),
            under: Some(dir),
            limit: 10,
            ..Default::default()
        },
    );
    assert_eq!(r.len(), 10);
    assert_eq!(r[0].name, "largest.dat");
}

fn synthetic(id: &str, category: Category, label: SafetyLabel, removal: Removal) -> Finding {
    Finding {
        id: FindingId(id.into()),
        category,
        title: id.into(),
        subtitle: None,
        path: None,
        node: None,
        allocated: 1000,
        logical: 1000,
        freed_if_deleted: 100,
        modified: None,
        label,
        rule_id: id.into(),
        explain: String::new(),
        removal,
        flags: vec![],
        components: Vec::new(),
    }
}

fn command(freed_note: Option<&str>) -> Removal {
    Removal::Command {
        tool: "t".into(),
        argv: vec!["t".into()],
        cwd: None,
        install_hint: None,
        freed_note: freed_note.map(str::to_string),
    }
}

#[test]
fn overview_excludes_partial_commands_from_safe_and_protected_data_from_categories() {
    let d = tempfile::tempdir().unwrap();
    let mut s = snap(d.path());
    s.findings = vec![
        synthetic(
            "full",
            Category::DevCaches,
            SafetyLabel::Regenerates,
            command(None),
        ),
        synthetic(
            "partial",
            Category::DevCaches,
            SafetyLabel::Regenerates,
            command(Some("Removes only part")),
        ),
        synthetic(
            "trash",
            Category::DevCaches,
            SafetyLabel::Regenerates,
            Removal::Trash { paths: vec![] },
        ),
        synthetic(
            "keychain",
            Category::AppCaches,
            SafetyLabel::DoNotTouch,
            Removal::None,
        ),
        synthetic(
            "data",
            Category::AppCaches,
            SafetyLabel::AppData,
            Removal::None,
        ),
    ];
    let o = disk_overview(Some(&s));
    assert_eq!(o.safe_to_free, 200, "the freed_note command is not counted");
    let bytes = |c: Category| o.by_category.iter().find(|(x, _)| *x == c).unwrap().1;
    assert_eq!(bytes(Category::DevCaches), 3000);
    assert_eq!(bytes(Category::AppCaches), 1000, "do-not-touch not counted");
    assert_eq!(o.protected_bytes, 1000);
}

#[test]
fn partial_clean_dev_cache_rules_carry_a_freed_note() {
    let rs = RuleSet::builtin();
    for id in ["cargo-registry", "cargo-git", "pnpm-store"] {
        let cmd = rs.get(id).unwrap().command.as_ref().unwrap();
        assert!(cmd.freed_note.is_some(), "{id}");
    }
}

#[test]
fn apps_weight_counts_bundles_only() {
    use discky_core::findings::{Component, ComponentKind, ComponentRemoval};
    let comp = |kind: ComponentKind, allocated: u64| Component {
        title: format!("{kind:?}"),
        kind,
        path: None,
        allocated,
        freed_if_deleted: allocated,
        modified: None,
        default_on: true,
        removal: ComponentRemoval::Trash,
        note: None,
        covered_by_cask: false,
    };
    let d = tempfile::tempdir().unwrap();
    let mut s = snap(d.path());
    // An app: bundle 500 + leftovers 300 (the leftovers' nodes may also be other
    // findings', e.g. app caches).
    let mut app = synthetic(
        "app",
        Category::Apps,
        SafetyLabel::AppData,
        Removal::Trash { paths: vec![] },
    );
    app.allocated = 800;
    app.components = vec![
        comp(ComponentKind::AppBundle, 500),
        comp(ComponentKind::Caches, 300),
    ];
    // A leftover group claims its nodes: it counts fully.
    let mut group = synthetic(
        "group",
        Category::Apps,
        SafetyLabel::AppData,
        Removal::Trash { paths: vec![] },
    );
    group.allocated = 70;
    group.components = vec![comp(ComponentKind::Caches, 70)];
    // No components at all: its own size.
    let plain = synthetic(
        "plain",
        Category::Apps,
        SafetyLabel::AppData,
        Removal::Trash { paths: vec![] },
    );
    s.findings = vec![app, group, plain];
    let o = disk_overview(Some(&s));
    let bytes = |c: Category| o.by_category.iter().find(|(x, _)| *x == c).unwrap().1;
    assert_eq!(bytes(Category::Apps), 500 + 70 + 1000);
}
