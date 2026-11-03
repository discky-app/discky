//! mise language versions: CLI JSON parsing, status, untracked version files, findings.
//! Pure: the JSON comes from fixtures (`tests/fixtures/mise`), files from a temp tree; no
//! test runs mise (except the `#[ignore]`d read-only check on the real machine).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use discky_core::findings::mise::{
    MiseSource, MiseVersion, RULE_ID, VersionStatus, find_with, merge_sources, parse_ls, status_of,
    untracked_version_files,
};
use discky_core::findings::{ComponentKind, ComponentRemoval, Removal};
use discky_core::fs::walk::{ScanOptions, walk};
use discky_core::index::Index;
use discky_core::rules::{Category, SafetyLabel};

const LS: &str = include_str!("fixtures/mise/ls.json");
const ALL: &str = include_str!("fixtures/mise/all_sources.json");
const HOME: &str = "/Users/me";

fn scan(root: &Path) -> Index {
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

fn get<'a>(vs: &'a [MiseVersion], tool: &str, version: &str) -> &'a MiseVersion {
    vs.iter()
        .find(|v| v.tool == tool && v.version == version)
        .unwrap_or_else(|| panic!("{tool}@{version} missing in {vs:?}"))
}

fn put(root: &Path, rel: &str, body: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn version(tool: &str, v: &str, install: PathBuf, sources: Vec<MiseSource>) -> MiseVersion {
    MiseVersion {
        tool: tool.into(),
        version: v.into(),
        install_path: install,
        installed: true,
        active: false,
        sources,
    }
}

#[test]
fn parse_ls_reads_versions_and_single_source() {
    let vs = parse_ls(LS).unwrap();
    assert_eq!(vs.len(), 8, "{vs:?}");
    let old = get(&vs, "node", "19.9.0");
    assert!(old.installed && !old.active);
    assert!(old.sources.is_empty());
    assert_eq!(
        old.install_path,
        PathBuf::from("/Users/me/.local/share/mise/installs/node/19.9.0")
    );
    let g = get(&vs, "node", "22.16.0");
    assert!(g.active);
    assert_eq!(
        g.sources,
        vec![MiseSource {
            kind: "mise.toml".into(),
            path: "/Users/me/.config/mise/config.toml".into(),
            requested: "22.16.0".into(),
        }]
    );
    assert_eq!(get(&vs, "python", "3.12.15").sources[0].requested, "3.12");
    assert_eq!(get(&vs, "pnpm", "12.15.0").sources[0].requested, "latest");

    assert!(parse_ls("not json").is_err());
    assert!(parse_ls("[1, 2]").is_err());
    assert_eq!(parse_ls("{}").unwrap(), Vec::new());
    // Malformed entries are skipped, not fatal.
    let vs = parse_ls(r#"{"node": [{"version": 1}, {"version": "1.0.0", "install_path": "/x", "installed": true}], "bad": 3}"#)
        .unwrap();
    assert_eq!(vs.len(), 1);
    assert!(vs[0].installed && !vs[0].active);
}

#[test]
fn merge_sources_keeps_unreferenced_and_drops_missing() {
    let vs = merge_sources(parse_ls(LS).unwrap(), ALL);
    assert_eq!(vs.len(), 8, "{vs:?}");
    assert!(get(&vs, "node", "19.9.0").sources.is_empty());
    let g = get(&vs, "node", "22.16.0");
    let kinds: Vec<&str> = g.sources.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["mise.toml", "idiomatic-version-file"]);
    assert_eq!(
        g.sources[1].path,
        PathBuf::from("/Users/me/Projects/project-b/.node-version")
    );
    let t = get(&vs, "node", "20.11.0");
    assert_eq!(t.sources.len(), 1);
    assert_eq!(t.sources[0].kind, ".tool-versions");
    assert!(
        !vs.iter()
            .any(|v| v.tool == "ruby" && (v.version == "2.4.2" || v.version == "3.1.3")),
        "installed: false entries are dropped"
    );
    assert!(vs.iter().all(|v| v.installed));

    // Unreadable --all-sources output: the `mise ls` data stays as it is.
    let plain = merge_sources(parse_ls(LS).unwrap(), "garbage");
    assert_eq!(plain, parse_ls(LS).unwrap());
}

#[test]
fn status_global_pinned_unreferenced() {
    let vs = merge_sources(parse_ls(LS).unwrap(), ALL);
    let home = Path::new(HOME);
    assert_eq!(
        status_of(get(&vs, "node", "22.16.0"), home),
        VersionStatus::Global
    );
    assert_eq!(
        status_of(get(&vs, "node", "24.18.1"), home),
        VersionStatus::Pinned(1)
    );
    assert_eq!(
        status_of(get(&vs, "node", "19.9.0"), home),
        VersionStatus::Unreferenced
    );
    // Another home: the config file is just one more requester.
    assert_eq!(
        status_of(get(&vs, "node", "22.16.0"), Path::new("/Users/other")),
        VersionStatus::Pinned(2)
    );
    // Two files of one project count once.
    let src = |p: &str| MiseSource {
        kind: "idiomatic-version-file".into(),
        path: p.into(),
        requested: "3.1.3".into(),
    };
    let v = version(
        "ruby",
        "3.1.3",
        "/x".into(),
        vec![
            src("/p/rmo/.ruby-version"),
            src("/p/rmo/Gemfile"),
            src("/p/q/Gemfile"),
        ],
    );
    assert_eq!(status_of(&v, home), VersionStatus::Pinned(2));
}

#[test]
fn untracked_version_file_is_reported() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    put(h, "a/.nvmrc", b"v20\n");
    put(h, "b/.python-version", b"# pinned\n3.12\n");
    put(
        h,
        "c/.tool-versions",
        b"# tools\nnode 24.18.1 22\nruby 3.4.12 # main\n",
    );
    put(
        h,
        "d/mise.toml",
        b"[tools]\nnode = [\"22\", \"20\"]\npython = \"3.12\"\n",
    );
    put(h, "e/.mise/config.toml", b"[tools]\nruby = \"3.4\"\n");
    put(h, "f/.ruby-version", b"ruby-3.4.12\n");
    put(h, "g/.mise.toml", b"this is = = not toml");
    put(h, "tracked/.node-version", b"24.18.1\n");
    put(h, "1/2/3/4/5/.node-version", b"25\n");
    // Ignored: too deep, under ~/Library, node_modules, .git, hidden dirs, too big.
    put(h, "1/2/3/4/5/6/.node-version", b"26\n");
    put(h, "Library/x/.nvmrc", b"18\n");
    put(h, "w/node_modules/p/.nvmrc", b"18\n");
    put(h, "w/.git/.nvmrc", b"18\n");
    put(h, ".hidden/.nvmrc", b"18\n");
    let mut big = b"19\n".to_vec();
    big.resize(5000, b'\n');
    put(h, "big/.nvmrc", &big);

    let idx = scan(h);
    let tracked: HashSet<PathBuf> = [h.join("tracked/.node-version")].into();
    let mut got = untracked_version_files(&idx, h, &tracked);
    got.sort();
    let want = |rel: &str, tool: &str, req: &str| (h.join(rel), tool.to_string(), req.to_string());
    let mut expected = vec![
        want("a/.nvmrc", "node", "20"),
        want("b/.python-version", "python", "3.12"),
        want("c/.tool-versions", "node", "24.18.1"),
        want("c/.tool-versions", "ruby", "3.4.12"),
        want("d/mise.toml", "node", "22"),
        want("d/mise.toml", "node", "20"),
        want("d/mise.toml", "python", "3.12"),
        want("e/.mise/config.toml", "ruby", "3.4"),
        want("f/.ruby-version", "ruby", "3.4.12"),
        want("1/2/3/4/5/.node-version", "node", "25"),
    ];
    expected.sort();
    assert_eq!(got, expected);

    // Matched to installed versions by prefix; requests for missing versions are ignored.
    let inst = |t: &str, v: &str| version(t, v, h.join(format!("installs/{t}/{v}")), Vec::new());
    let vs = vec![
        inst("node", "20.11.0"),
        inst("node", "19.9.0"),
        inst("python", "3.12.15"),
    ];
    let mut claimed = HashSet::new();
    let f = find_with(&vs, &got, &idx, h, &mut claimed);
    let node20 = f.iter().find(|f| f.title == "node 20.11.0").unwrap();
    assert_eq!(
        node20.subtitle.as_deref(),
        Some("not referenced · 2 untracked files")
    );
    let titles: Vec<&str> = node20.components.iter().map(|c| c.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "requested by .nvmrc · not tracked by mise",
            "requested by mise.toml · not tracked by mise"
        ]
    );
    let c = &node20.components[0];
    assert_eq!(c.kind, ComponentKind::Project);
    assert_eq!(c.path.as_deref(), Some(h.join("a/.nvmrc").as_path()));
    assert_eq!(c.note.as_deref(), Some("not tracked by mise"));
    assert!(!c.default_on);
    assert_eq!(c.removal, ComponentRemoval::None);
    let py = f.iter().find(|f| f.title == "python 3.12.15").unwrap();
    assert_eq!(
        py.subtitle.as_deref(),
        Some("not referenced · 2 untracked files")
    );
    let node19 = f.iter().find(|f| f.title == "node 19.9.0").unwrap();
    assert_eq!(node19.subtitle.as_deref(), Some("not referenced"));
    assert!(node19.components.is_empty(), "\"2\" must not match 19.9.0");
}

#[test]
fn global_version_is_not_removable() {
    let empty = tempfile::tempdir().unwrap();
    let idx = scan(empty.path());
    let vs = merge_sources(parse_ls(LS).unwrap(), ALL);
    let mut claimed = HashSet::new();
    let f = find_with(&vs, &[], &idx, Path::new(HOME), &mut claimed);
    assert_eq!(f.len(), 8);
    assert!(claimed.is_empty(), "nothing in the index to claim");

    let g = f.iter().find(|f| f.title == "node 22.16.0").unwrap();
    assert_eq!(g.removal, Removal::None);
    assert_eq!(g.subtitle.as_deref(), Some("global"));
    assert!(
        g.explain
            .starts_with("Global version; change it in ~/.config/mise/config.toml first"),
        "{}",
        g.explain
    );
    assert_eq!(g.rule_id, RULE_ID);
    assert_eq!(RULE_ID, "mise-version");
    assert_eq!(g.category, Category::LanguageVersions);
    assert_eq!(g.label, SafetyLabel::AppData);
    let titles: Vec<&str> = g.components.iter().map(|c| c.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "requested by ~/.config/mise/config.toml (global)",
            "requested by .node-version"
        ]
    );
    assert!(g.components.iter().all(|c| c.kind == ComponentKind::Project
        && !c.default_on
        && c.removal == ComponentRemoval::None
        && c.note.is_none()));
    assert_eq!(
        g.components[1].path.as_deref(),
        Some(Path::new("/Users/me/Projects/project-b/.node-version"))
    );

    let old = f.iter().find(|f| f.title == "node 19.9.0").unwrap();
    assert_eq!(
        old.removal,
        Removal::MiseUninstall {
            tool: "node".into(),
            version: "19.9.0".into()
        }
    );
    assert_eq!(old.subtitle.as_deref(), Some("not referenced"));
    assert_eq!(
        old.path.as_deref(),
        Some(Path::new(
            "/Users/me/.local/share/mise/installs/node/19.9.0"
        ))
    );
    assert_eq!(
        (old.allocated, old.freed_if_deleted, old.node),
        (0, 0, None)
    );
    assert!(
        old.explain.ends_with("(size unknown: outside scan roots)"),
        "{}",
        old.explain
    );

    let pinned = f.iter().find(|f| f.title == "node 24.18.1").unwrap();
    assert_eq!(pinned.subtitle.as_deref(), Some("pinned in 1 project"));
    assert_eq!(pinned.components[0].title, "requested by .node-version");
    let t = f.iter().find(|f| f.title == "node 20.11.0").unwrap();
    assert_eq!(t.components[0].title, "requested by .tool-versions");
    assert!(matches!(pinned.removal, Removal::MiseUninstall { .. }));

    // The planner recognises the global version by the shared rule id.
    let p = discky_core::plan::plan_items_with_tools(
        &[discky_core::PlanItem {
            id: g.id.0.clone(),
            components: None,
            parts: None,
        }],
        &[g],
        &discky_core::Config::default(),
        &discky_core::plan::PlanTools::default(),
    );
    assert!(p.steps.is_empty());
    assert_eq!(p.skipped.len(), 1);
}

#[test]
fn findings_size_from_index_ignoring_alias_symlinks() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    let node = h.join(".local/share/mise/installs/node");
    put(&node, "19.9.0/bin/node", &vec![7u8; 256 * 1024]);
    put(&node, "19.9.0/lib/x.js", &vec![7u8; 64 * 1024]);
    for alias in ["19", "19.9", "lts-iron", "latest"] {
        std::os::unix::fs::symlink("./19.9.0", node.join(alias)).unwrap();
    }
    let idx = scan(h);
    let vs = vec![
        version("node", "19.9.0", node.join("19.9.0"), Vec::new()),
        version(
            "node",
            "99.0.0",
            PathBuf::from("/nowhere/node/99.0.0"),
            Vec::new(),
        ),
    ];
    let mut claimed = HashSet::new();
    let f = find_with(&vs, &[], &idx, h, &mut claimed);
    assert_eq!(f.len(), 2, "aliases are not findings: {f:?}");
    let v = f.iter().find(|f| f.title == "node 19.9.0").unwrap();
    let id = idx.find(&node.join("19.9.0")).unwrap();
    let n = idx.node(id);
    assert_eq!(v.node, Some(id));
    assert_eq!(v.allocated, n.agg_allocated);
    assert_eq!(v.freed_if_deleted, n.agg_private);
    assert!(v.allocated >= 320 * 1024, "{}", v.allocated);
    assert_eq!(v.path.as_deref(), Some(node.join("19.9.0").as_path()));
    assert!(!v.explain.contains("size unknown"));
    assert_eq!(
        claimed,
        HashSet::from([id]),
        "only the version dir is claimed"
    );
    for alias in ["19", "latest"] {
        assert!(!claimed.contains(&idx.find(&node.join(alias)).unwrap()));
    }
    let missing = f.iter().find(|f| f.title == "node 99.0.0").unwrap();
    assert_eq!(missing.allocated, 0);
    assert!(
        missing
            .explain
            .contains("(size unknown: outside scan roots)")
    );

    // A version an earlier pass already claimed is not reported twice.
    let again = find_with(&vs[..1], &[], &idx, h, &mut claimed);
    assert!(again.is_empty(), "{again:?}");
}

/// Read-only check on this Mac: `cargo test -p discky-core --test mise -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_mise_counts() {
    let mise = discky_core::tools::tool_path("mise").expect("mise installed");
    let t = std::time::Duration::from_secs(5);
    let ls = discky_core::tools::run_capture(&mise, &["ls", "--json"], t).unwrap();
    let all = discky_core::tools::run_capture(&mise, &["ls", "--all-sources", "--json"], t)
        .unwrap_or_default();
    let vs = merge_sources(parse_ls(&ls).unwrap(), &all);
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let mut counts = std::collections::BTreeMap::new();
    for v in &vs {
        *counts
            .entry(format!("{:?}", status_of(v, &home)))
            .or_insert(0) += 1;
    }
    println!("installed versions: {} {counts:?}", vs.len());
    for v in &vs {
        println!("  {} {} {:?}", v.tool, v.version, status_of(v, &home));
    }
    // Untracked version files in one projects folder only (a full home walk is slow).
    // The first of a few usual projects folders that exists.
    let projects = ["Projects", "Developer", "src", "code"]
        .iter()
        .map(|p| home.join(p))
        .find(|p| p.is_dir());
    if let Some(projects) = projects {
        let tracked: HashSet<PathBuf> = parse_ls(&all)
            .unwrap_or_default()
            .into_iter()
            .flat_map(|v| v.sources)
            .map(|s| s.path)
            .collect();
        let idx = scan(&projects);
        let files = untracked_version_files(&idx, &home, &tracked);
        let mut claimed = HashSet::new();
        let f = find_with(&vs, &files, &idx, &home, &mut claimed);
        let attached: usize = f
            .iter()
            .flat_map(|f| &f.components)
            .filter(|c| c.note.is_some())
            .count();
        println!(
            "untracked version-file requests under {}: {} ({attached} attached to installed versions)",
            projects.display(),
            files.len()
        );
        for f in &f {
            println!("  {} · {}", f.title, f.subtitle.as_deref().unwrap_or(""));
        }
    }
    let prune =
        discky_core::tools::run_capture_all(&mise, &["prune", "-n"], &[("NO_COLOR", "1")], t);
    println!(
        "mise prune -n: {} lines",
        prune.unwrap_or_default().trim().lines().count()
    );
}
