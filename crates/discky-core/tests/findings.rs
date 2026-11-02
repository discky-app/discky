mod fixtures;
use discky_core::{
    config::Thresholds,
    findings::{Categorizer, Removal},
    fs::walk::{ScanOptions, walk},
    rules::{Category, RuleSet, SafetyLabel},
};

fn scan(root: &std::path::Path) -> discky_core::index::Index {
    walk(
        &ScanOptions {
            roots: vec![root.into()],
            exclude: globset::GlobSet::empty(),
            threads: 0,
            exact_private_size: false,
        },
        &|_| {},
    )
}

#[test]
fn build_dirs_become_project_build_findings_with_cwd_command() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let f = Categorizer {
        index: &idx,
        rules: &RuleSet::builtin(),
        thresholds: &Thresholds::default(),
    }
    .run();
    let t = f
        .iter()
        .find(|f| f.rule_id == "cargo-target")
        .expect("cargo target finding");
    assert!(matches!(t.category, Category::ProjectBuilds));
    assert!(
        matches!(&t.removal, Removal::Command { argv, cwd: Some(c), .. } if argv == &["cargo","clean"] && c == &d.path().join("proj"))
    );
    assert!(f.iter().any(|f| f.rule_id == "node-modules"));
}

#[test]
fn large_file_is_found_with_sparse_flag_and_honest_size() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let th = Thresholds {
        large_file_bytes: 100 * 1024 * 1024,
        old_days: 365,
    };
    let f = Categorizer {
        index: &idx,
        rules: &RuleSet::builtin(),
        thresholds: &th,
    }
    .run();
    let big = f
        .iter()
        .find(|f| f.path.as_deref() == Some(&d.path().join("big.bin")))
        .unwrap();
    assert!(matches!(big.category, Category::LargeOld));
    assert!(big.flags.iter().any(|x| x == "sparse"));
    assert!(big.allocated < 1024 * 1024 && big.logical >= 600 * 1024 * 1024);
}

#[test]
fn old_dir_is_found_and_claimed_nodes_are_not_double_reported() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let f = Categorizer {
        index: &idx,
        rules: &RuleSet::builtin(),
        thresholds: &Thresholds::default(),
    }
    .run();
    assert!(
        f.iter()
            .any(|f| f.path.as_deref() == Some(&d.path().join("old"))
                && matches!(f.category, Category::LargeOld))
    );
    let target = d.path().join("proj/target");
    assert_eq!(
        f.iter()
            .filter(|f| f.path.as_deref().is_some_and(|p| p.starts_with(&target)))
            .count(),
        1
    );
}

#[test]
fn finding_ids_are_stable_across_scans() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let rs = RuleSet::builtin();
    let th = Thresholds::default();
    let a = Categorizer {
        index: &scan(d.path()),
        rules: &rs,
        thresholds: &th,
    }
    .run();
    let b = Categorizer {
        index: &scan(d.path()),
        rules: &rs,
        thresholds: &th,
    }
    .run();
    let ids = |v: &Vec<discky_core::findings::Finding>| {
        v.iter()
            .map(|f| f.id.0.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert!(!a.is_empty());
    assert_eq!(ids(&a), ids(&b));
}

#[test]
fn do_not_touch_rules_yield_no_removal() {
    let d = tempfile::tempdir().unwrap();
    let toml = format!(
        "[[rule]]\nid=\"kc\"\ncategory=\"app_caches\"\nlabel=\"do_not_touch\"\ntitle=\"Keychains\"\nexplain=\"Never.\"\n[rule.matcher]\nkind=\"path\"\npath=\"{}\"\n",
        d.path().join("kc").display()
    );
    std::fs::create_dir(d.path().join("kc")).unwrap();
    let rs = RuleSet::from_toml(&toml).unwrap();
    let idx = scan(d.path());
    let f = Categorizer {
        index: &idx,
        rules: &rs,
        thresholds: &Thresholds::default(),
    }
    .run();
    assert!(matches!(f[0].removal, Removal::None));
    assert!(matches!(f[0].label, SafetyLabel::DoNotTouch));
}

fn old_mtime(p: &std::path::Path) {
    let t = filetime::FileTime::from_unix_time(1_000_000_000, 0);
    filetime::set_file_mtime(p, t).unwrap();
}

#[test]
fn per_child_rule_emits_one_finding_per_child_dir() {
    let d = tempfile::tempdir().unwrap();
    let hub = d.path().join("hub");
    std::fs::create_dir_all(hub.join("models--a")).unwrap();
    std::fs::create_dir_all(hub.join("models--b")).unwrap();
    std::fs::write(hub.join("version.txt"), "1").unwrap();
    let toml = format!(
        "[[rule]]\nid=\"hub\"\ncategory=\"models\"\nlabel=\"regenerates\"\ntitle=\"Hub\"\nexplain=\"x\"\nper_child=true\n[rule.matcher]\nkind=\"path\"\npath=\"{}\"\n",
        hub.display()
    );
    let rs = RuleSet::from_toml(&toml).unwrap();
    let idx = scan(d.path());
    let f = Categorizer {
        index: &idx,
        rules: &rs,
        thresholds: &Thresholds::default(),
    }
    .run();
    let mut titles: Vec<_> = f
        .iter()
        .filter(|f| f.rule_id == "hub")
        .map(|f| f.title.as_str())
        .collect();
    titles.sort();
    assert_eq!(titles, ["models--a", "models--b"]);
    assert!(!f.iter().any(|f| f.path.as_deref() == Some(&hub)));
}

#[test]
fn old_dir_containing_a_do_not_touch_rule_is_not_reported_whole() {
    let d = tempfile::tempdir().unwrap();
    let keep = d.path().join("archive/keep");
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::create_dir_all(d.path().join("archive/stale")).unwrap();
    for p in ["archive/keep", "archive/stale", "archive"] {
        old_mtime(&d.path().join(p));
    }
    let toml = format!(
        "[[rule]]\nid=\"keep\"\ncategory=\"app_caches\"\nlabel=\"do_not_touch\"\ntitle=\"Keep\"\nexplain=\"x\"\n[rule.matcher]\nkind=\"path\"\npath=\"{}\"\n",
        keep.display()
    );
    let rs = RuleSet::from_toml(&toml).unwrap();
    let idx = scan(d.path());
    let f = Categorizer {
        index: &idx,
        rules: &rs,
        thresholds: &Thresholds::default(),
    }
    .run();
    let paths: Vec<_> = f.iter().filter_map(|f| f.path.clone()).collect();
    assert!(!paths.contains(&d.path().join("archive")));
    assert!(paths.contains(&d.path().join("archive/stale")));
    assert!(paths.contains(&keep));
}

#[test]
fn build_dir_modified_ignores_the_build_dir_itself() {
    let d = tempfile::tempdir().unwrap();
    let proj = d.path().join("proj");
    std::fs::create_dir_all(proj.join("target/debug")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "").unwrap();
    old_mtime(&proj.join("Cargo.toml"));
    old_mtime(&proj);
    let idx = scan(d.path());
    let f = Categorizer {
        index: &idx,
        rules: &RuleSet::builtin(),
        thresholds: &Thresholds::default(),
    }
    .run();
    let t = f.iter().find(|f| f.rule_id == "cargo-target").unwrap();
    assert_eq!(t.modified, Some(1_000_000_000));
}

/// Manual sanity check on the real home: `cargo test --release -p discky-core --test findings -- --ignored --nocapture`.
#[test]
#[ignore]
fn categorize_home() {
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap());
    let t = std::time::Instant::now();
    let idx = scan(&home);
    let scanned = t.elapsed();
    let rs = RuleSet::builtin();
    let th = Thresholds::default();
    let t = std::time::Instant::now();
    let f = Categorizer {
        index: &idx,
        rules: &rs,
        thresholds: &th,
    }
    .run();
    println!(
        "{} nodes scanned in {scanned:?}; {} findings in {:?}",
        idx.len(),
        f.len(),
        t.elapsed()
    );
    for x in f.iter().take(25) {
        println!(
            "{:>8} MiB {:<16} {:?} {:?}",
            x.freed_if_deleted >> 20,
            x.rule_id,
            x.path,
            x.flags
        );
    }
}
