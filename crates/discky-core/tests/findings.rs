mod fixtures;
use discky_core::{
    config::Thresholds,
    findings::{Categorizer, Finding, Removal},
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
            cancel: None,
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
    .run_with_home(Some(d.path()));
    let t = f
        .iter()
        .find(|f| f.rule_id == "cargo-target")
        .expect("cargo target finding");
    assert!(matches!(t.category, Category::ProjectBuilds));
    let target = d.path().join("proj/target");
    let want = ["cargo", "clean", "--target-dir", target.to_str().unwrap()];
    assert!(
        matches!(&t.removal, Removal::Command { argv, cwd: Some(c), .. } if argv == &want && c == &d.path().join("proj")),
        "{:?}",
        t.removal
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
    .run_with_home(Some(d.path()));
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
    .run_with_home(Some(d.path()));
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
    .run_with_home(Some(d.path()));
    let b = Categorizer {
        index: &scan(d.path()),
        rules: &rs,
        thresholds: &th,
    }
    .run_with_home(Some(d.path()));
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
    .run_with_home(Some(d.path()));
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
    .run_with_home(Some(d.path()));
    let t = f.iter().find(|f| f.rule_id == "cargo-target").unwrap();
    assert_eq!(t.modified, Some(1_000_000_000));
}

fn categorize(idx: &discky_core::index::Index, home: &std::path::Path) -> Vec<Finding> {
    Categorizer {
        index: idx,
        rules: &RuleSet::builtin(),
        thresholds: &Thresholds::default(),
    }
    .run_with_home(Some(home))
}

#[test]
fn build_dirs_inside_app_bundles_and_packages_are_never_reported() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    let put = |rel: &str| {
        let p = h.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"{}").unwrap();
    };
    let app = h.join("X.app");
    put("X.app/Contents/Resources/app/package.json");
    put("X.app/Contents/Resources/app/node_modules/m/index.js");
    put("X.app/Contents/Resources/app/extensions/e/package.json");
    put("X.app/Contents/Resources/app/extensions/e/dist/main.js");
    // Build-like dirs below a package's node_modules belong to the package.
    put("web/node_modules/pkg/package.json");
    put("web/node_modules/pkg/dist/index.js");
    // A tool install under an excluded home tree.
    put(".local/share/mise/installs/node/19/lib/node_modules/corepack/package.json");
    put(".local/share/mise/installs/node/19/lib/node_modules/corepack/dist/c.js");
    put("proj/Cargo.toml");
    put("proj/target/debug/a.rlib");
    let f = categorize(&scan(h), h);
    let builds: Vec<_> = f
        .iter()
        .filter(|f| f.category == Category::ProjectBuilds)
        .filter_map(|f| f.path.clone())
        .collect();
    assert!(!builds.iter().any(|p| p.starts_with(&app)), "{builds:?}");
    assert!(
        !builds
            .iter()
            .any(|p| p.starts_with(h.join("web/node_modules/pkg"))),
        "{builds:?}"
    );
    assert!(
        !builds.iter().any(|p| p.starts_with(h.join(".local"))),
        "{builds:?}"
    );
    assert!(builds.contains(&h.join("proj/target")), "{builds:?}");

    // A root outside home: no project builds at all.
    let elsewhere = tempfile::tempdir().unwrap();
    let f = categorize(&scan(h), elsewhere.path());
    assert!(
        !f.iter().any(|f| f.category == Category::ProjectBuilds),
        "{f:?}"
    );
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

fn large_old_with_home(
    idx: &discky_core::index::Index,
    home: &std::path::Path,
) -> Vec<discky_core::findings::Finding> {
    discky_core::findings::large_old::find(
        idx,
        &Thresholds::default(),
        Some(home),
        &mut std::collections::HashSet::new(),
    )
}

#[test]
fn vcs_dirs_are_opaque_and_reported_once_without_removal() {
    let d = tempfile::tempdir().unwrap();
    let git = d.path().join("repo/.git");
    std::fs::create_dir_all(git.join("objects/pack")).unwrap();
    std::fs::create_dir_all(git.join("objects/ab")).unwrap();
    old_mtime(&git.join("objects/ab"));
    let pack = std::fs::File::create(git.join("objects/pack/big.pack")).unwrap();
    pack.set_len(Thresholds::default().large_file_bytes + 1)
        .unwrap();
    drop(pack);
    let idx = scan(d.path());
    let f = large_old_with_home(&idx, d.path());
    let under: Vec<_> = f
        .iter()
        .filter(|f| f.path.as_deref().is_some_and(|p| p.starts_with(&git)))
        .collect();
    assert_eq!(under.len(), 1, "{under:?}");
    let g = under[0];
    assert_eq!(g.path.as_deref(), Some(git.as_path()));
    assert!(matches!(g.category, Category::LargeOld));
    assert!(matches!(g.removal, Removal::None));
    assert_eq!(g.rule_id, "vcs-history");
    assert_eq!(g.title, "Git history");
    assert_eq!(g.subtitle.as_deref(), Some("repo"));
}

#[test]
fn small_vcs_dirs_are_skipped_entirely() {
    let d = tempfile::tempdir().unwrap();
    let git = d.path().join("repo/.git/objects/ab");
    std::fs::create_dir_all(&git).unwrap();
    old_mtime(&git);
    let idx = scan(d.path());
    let f = large_old_with_home(&idx, d.path());
    assert!(!f.iter().any(|f| {
        f.path
            .as_deref()
            .is_some_and(|p| p.starts_with(d.path().join("repo/.git")))
    }));
}

#[test]
fn large_old_ignores_roots_outside_home() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let elsewhere = tempfile::tempdir().unwrap();
    assert!(large_old_with_home(&idx, elsewhere.path()).is_empty());
}

#[test]
fn downloads_children_are_always_reported() {
    let d = tempfile::tempdir().unwrap();
    let downloads = d.path().join("Downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::write(downloads.join("small.txt"), "hi").unwrap();
    let idx = scan(d.path());
    let f = large_old_with_home(&idx, d.path());
    let small = f
        .iter()
        .find(|f| f.path.as_deref() == Some(&downloads.join("small.txt")))
        .expect("Downloads child reported");
    assert_eq!(small.subtitle.as_deref(), Some("Downloads"));
    assert!(
        !f.iter()
            .any(|f| f.path.as_deref() == Some(downloads.as_path()))
    );
}
