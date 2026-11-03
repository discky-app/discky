//! App findings: leftovers attached to installed apps, leftover groups of removed apps
//! and orphan package receipts. Temp trees scanned with `walk`; synthetic `AppInfo`s,
//! casks, receipts and `running` sets; no external command is ever run (`launchctl:
//! None`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use discky_core::findings::apps::cask::{Cask, Directive};
use discky_core::findings::apps::leftovers::{launchd_label, preference_domains};
use discky_core::findings::apps::pkg::PkgReceipt;
use discky_core::findings::apps::{AppInfo, AppsInput, LastUsed, UNUSED_DAYS, find_with};
use discky_core::findings::{
    AppSource, ComponentKind, ComponentRemoval, Finding, FindingId, Removal, app_caches,
};
use discky_core::fs::walk::{ScanOptions, walk};
use discky_core::index::Index;
use discky_core::rules::{Category, SafetyLabel};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/apps");
const NOW: i64 = 1_793_709_308; // 2026-11-03 12:35:08 UTC
const DAY: i64 = 86_400;

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

/// A directory `root/rel` holding one `kb`-KiB file.
fn blob(root: &Path, rel: &str, kb: usize) -> PathBuf {
    let dir = root.join(rel);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("blob"), vec![1u8; kb * 1024]).unwrap();
    dir
}

/// A file `root/rel` of `kb` KiB.
fn file(root: &Path, rel: &str, kb: usize) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, vec![1u8; kb * 1024]).unwrap();
    p
}

fn make_app(path: &Path, bundle_id: &str) {
    let contents = path.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    let mut dict = plist::Dictionary::new();
    dict.insert("CFBundleIdentifier".into(), bundle_id.into());
    plist::Value::Dictionary(dict)
        .to_file_xml(contents.join("Info.plist"))
        .unwrap();
    std::fs::write(contents.join("MacOS/bin"), vec![1u8; 64 * 1024]).unwrap();
}

fn app(idx: &Index, bundle: &Path, id: &str, source: AppSource, last: LastUsed) -> AppInfo {
    AppInfo {
        bundle: bundle.to_path_buf(),
        node: idx.find(bundle).expect("bundle in index"),
        name: bundle.file_stem().unwrap().to_string_lossy().into_owned(),
        bundle_id: Some(id.to_string()),
        version: Some("1.0".into()),
        source,
        last_used: last,
        own_uninstaller: None,
        root_owned: false,
    }
}

struct Ctx {
    casks: Vec<Cask>,
    receipts: Vec<PkgReceipt>,
    running: HashSet<String>,
    other: HashMap<String, String>,
    system_library: PathBuf,
}

impl Ctx {
    fn new(root: &Path) -> Ctx {
        Ctx {
            casks: Vec::new(),
            receipts: Vec::new(),
            running: HashSet::new(),
            other: HashMap::new(),
            system_library: root.join("Library"),
        }
    }

    fn run(
        &self,
        idx: &Index,
        home: &Path,
        apps: &[AppInfo],
        claimed: &mut HashSet<discky_core::index::NodeId>,
    ) -> Vec<Finding> {
        find_with(
            idx,
            home,
            claimed,
            &AppsInput {
                apps,
                casks: &self.casks,
                receipts: &self.receipts,
                running: &self.running,
                other_installed: &self.other,
                launchctl: None,
                system_library: &self.system_library,
                now: NOW,
            },
        )
    }
}

fn component_paths(f: &Finding) -> Vec<PathBuf> {
    f.components.iter().filter_map(|c| c.path.clone()).collect()
}

fn component<'a>(f: &'a Finding, path: &Path) -> &'a discky_core::findings::Component {
    f.components
        .iter()
        .find(|c| c.path.as_deref() == Some(path))
        .unwrap_or_else(|| panic!("no component {path:?} in {:#?}", f.components))
}

#[test]
fn app_finding_lists_bundle_and_leftovers() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let bundle = root.join("Applications/Raycast.app");
    make_app(&bundle, "com.raycast.macos");
    let support = blob(&home, "Library/Application Support/com.raycast.macos", 2048);
    let backups = blob(
        &home,
        "Library/Application Support/.com.raycast.macos.backups",
        512,
    );
    let caches = blob(&home, "Library/Caches/com.raycast.macos", 1024);
    let prefs = file(&home, "Library/Preferences/com.raycast.macos.plist", 4);
    let group = blob(
        &home,
        "Library/Group Containers/SY64MV22J9.com.raycast.macos.shared",
        8,
    );
    let other_prefix = blob(&home, "Library/Caches/com.raycast.macosx", 8);
    let zap = blob(&home, ".config/raycast", 16);
    let idx = scan(root);

    let mut ctx = Ctx::new(root);
    ctx.casks = vec![Cask {
        token: "raycast".into(),
        full_token: "raycast".into(),
        installed: Some("1.0".into()),
        app_targets: vec![bundle.clone()],
        uninstall: Vec::new(),
        zap: vec![Directive {
            trash: vec!["~/.config/raycast".into()],
            ..Default::default()
        }],
    }];
    let apps = [app(
        &idx,
        &bundle,
        "com.raycast.macos",
        AppSource::Cask {
            token: "raycast".into(),
            full_token: "raycast".into(),
        },
        LastUsed::Spotlight(NOW - 90 * DAY),
    )];
    let mut claimed = HashSet::new();
    let found = ctx.run(&idx, &home, &apps, &mut claimed);
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = &found[0];
    assert_eq!(f.id, FindingId::new("app", &bundle.to_string_lossy()));
    assert_eq!(f.category, Category::Apps);
    assert_eq!(f.title, "Raycast");
    assert_eq!(
        f.subtitle.as_deref(),
        Some("cask · raycast · last opened 3 months ago")
    );
    assert_eq!(f.path.as_deref(), Some(bundle.as_path()));
    assert_eq!(f.modified, Some(NOW - 90 * DAY));
    assert_eq!(f.label, SafetyLabel::AppData);
    assert!(!f.flags.iter().any(|x| x == "app-running"));
    assert!(matches!(
        &f.removal,
        Removal::App { bundle: b, bundle_id: Some(id), source: AppSource::Cask { .. } }
            if b == &bundle && id == "com.raycast.macos"
    ));
    assert!(f.explain.contains("brew uninstall --zap"), "{}", f.explain);

    // Bundle first, Keychain line last, leftovers in between sorted by size.
    assert_eq!(f.components[0].kind, ComponentKind::AppBundle);
    assert_eq!(f.components[0].path.as_deref(), Some(bundle.as_path()));
    let last = f.components.last().unwrap();
    assert_eq!(last.title, "Keychain items");
    assert_eq!(last.removal, ComponentRemoval::None);
    assert!(!last.default_on);
    let middle = &f.components[1..f.components.len() - 1];
    assert!(middle.windows(2).all(|w| w[0].allocated >= w[1].allocated));

    let paths = component_paths(f);
    for p in [&support, &backups, &caches, &prefs, &group, &zap] {
        assert!(paths.contains(p), "{p:?} missing from {paths:#?}");
    }
    assert!(
        !paths.contains(&other_prefix),
        "com.raycast.macosx is another bundle id"
    );
    assert_eq!(
        component(f, &support).kind,
        ComponentKind::ApplicationSupport
    );
    assert_eq!(component(f, &group).kind, ComponentKind::GroupContainer);
    let p = component(f, &prefs);
    assert_eq!(p.kind, ComponentKind::Preferences);
    assert_eq!(
        p.removal,
        ComponentRemoval::Defaults {
            domain: "com.raycast.macos".into()
        }
    );
    assert_eq!(component(f, &caches).removal, ComponentRemoval::Trash);
    assert!(
        f.components[..f.components.len() - 1]
            .iter()
            .all(|c| c.default_on)
    );

    let sum: u64 = f
        .components
        .iter()
        .filter(|c| c.default_on)
        .map(|c| c.allocated)
        .sum();
    assert_eq!(f.allocated, sum);
    assert!(f.allocated > 3 * 1024 * 1024);
    let freed: u64 = f
        .components
        .iter()
        .filter(|c| c.default_on)
        .map(|c| c.freed_if_deleted)
        .sum();
    assert_eq!(f.freed_if_deleted, freed);

    // Apps do not claim: App caches still lists Raycast's folders.
    assert!(claimed.is_empty(), "apps claim nothing");
    let caches_found = app_caches::find(&idx, &home, &mut claimed);
    assert!(
        caches_found
            .iter()
            .any(|c| c.path.as_deref() == Some(&*support))
    );

    assert_eq!(
        preference_domains(&home, "com.raycast.macos"),
        vec![("com.raycast.macos".to_string(), prefs.clone())]
    );
    assert_eq!(UNUSED_DAYS, 180);
}

#[test]
fn last_used_estimates_are_starred() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let things = root.join("Applications/Things3.app");
    make_app(&things, "com.culturedcode.ThingsMac");
    let lonely = root.join("Applications/Lonely.app");
    make_app(&lonely, "com.example.lonely");
    let support = blob(&home, "Library/Containers/com.culturedcode.ThingsMac", 8);
    let t = NOW - 425 * DAY;
    filetime::set_file_mtime(
        support.join("blob"),
        filetime::FileTime::from_unix_time(t, 0),
    )
    .unwrap();
    filetime::set_file_mtime(&support, filetime::FileTime::from_unix_time(t, 0)).unwrap();
    let idx = scan(root);
    let apps = [
        app(
            &idx,
            &things,
            "com.culturedcode.ThingsMac",
            AppSource::AppStore,
            LastUsed::Unknown,
        ),
        app(
            &idx,
            &lonely,
            "com.example.lonely",
            AppSource::Dragged,
            LastUsed::Unknown,
        ),
    ];
    let found = Ctx::new(root).run(&idx, &home, &apps, &mut HashSet::new());
    let things_f = found.iter().find(|f| f.title == "Things3").unwrap();
    assert_eq!(
        things_f.subtitle.as_deref(),
        Some("App Store · last opened 14 months ago*")
    );
    assert_eq!(things_f.modified, Some(t));
    let lonely_f = found.iter().find(|f| f.title == "Lonely").unwrap();
    assert_eq!(
        lonely_f.subtitle.as_deref(),
        Some("drag & drop · never opened*")
    );
    assert_eq!(lonely_f.modified, None);
}

#[test]
fn shared_leftover_is_attached_to_no_app() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let chrome = root.join("Applications/Google Chrome.app");
    make_app(&chrome, "com.google.Chrome");
    let drive = root.join("Applications/Google Drive.app");
    make_app(&drive, "com.google.drivefs");
    let own = blob(&home, "Library/Application Support/com.google.Chrome", 1024);
    let google = blob(&home, "Library/Application Support/Google", 2048);
    let keystone = blob(&home, "Library/Caches/com.google.Keystone", 512);
    let idx = scan(root);

    let mut ctx = Ctx::new(root);
    ctx.casks = vec![Cask {
        token: "google-chrome".into(),
        full_token: "google-chrome".into(),
        installed: Some("1".into()),
        app_targets: vec![chrome.clone()],
        uninstall: Vec::new(),
        zap: vec![Directive {
            trash: vec!["~/Library/Caches/com.google.Keystone".into()],
            rmdir: vec!["~/Library/Application Support/Google".into()],
            ..Default::default()
        }],
    }];
    let apps = [
        app(
            &idx,
            &chrome,
            "com.google.Chrome",
            AppSource::Cask {
                token: "google-chrome".into(),
                full_token: "google-chrome".into(),
            },
            LastUsed::Spotlight(NOW),
        ),
        app(
            &idx,
            &drive,
            "com.google.drivefs",
            AppSource::Dragged,
            LastUsed::Spotlight(NOW),
        ),
    ];
    let found = ctx.run(&idx, &home, &apps, &mut HashSet::new());
    let c = found.iter().find(|f| f.title == "Google Chrome").unwrap();
    assert!(component(c, &own).default_on);
    for shared in [&google, &keystone] {
        let s = component(c, shared);
        assert_eq!(s.removal, ComponentRemoval::None, "{shared:?}");
        assert!(!s.default_on);
        assert_eq!(s.note.as_deref(), Some("shared with Google Drive"));
    }
    for shared in [&google, &keystone] {
        assert!(
            !component(c, shared).covered_by_cask,
            "{shared:?}: shared, never covered"
        );
    }
    assert!(
        c.flags.iter().any(|x| x == "zap-shared"),
        "the zap stanza names a shared folder: {:?}",
        c.flags
    );
    let bundle_alloc = c.components[0].allocated;
    assert_eq!(c.allocated, bundle_alloc + component(c, &own).allocated);

    let dr = found.iter().find(|f| f.title == "Google Drive").unwrap();
    let dr_paths = component_paths(dr);
    assert!(!dr_paths.contains(&google) && !dr_paths.contains(&keystone));
    assert!(
        !found.iter().any(|f| f.rule_id == "app-leftovers"),
        "com.google is in use: {found:#?}"
    );
}

/// The Zoom tree from the research: user folders, a Logitech log folder that only
/// contains "zoom", and system-level agents/daemon/helper.
fn zoom_tree(root: &Path) -> (PathBuf, PathBuf) {
    let home = root.join("home");
    let bundle = root.join("Applications/zoom.us.app");
    make_app(&bundle, "us.zoom.xos");
    blob(&home, "Library/Application Support/zoom.us", 1024);
    blob(&home, "Library/Logs/zoom.us", 8);
    blob(&home, "Library/Logs/LogiZoomBridge", 8);
    blob(&home, "Library/Application Support/ZoomUpdater", 8);
    blob(&home, "Library/Caches/us.zoom.xos", 256);
    file(&home, "Library/Preferences/us.zoom.xos.plist", 4);
    let daemons = root.join("Library/LaunchDaemons");
    std::fs::create_dir_all(&daemons).unwrap();
    std::fs::copy(
        Path::new(FIXTURES).join("us.zoom.ZoomDaemon.plist"),
        daemons.join("us.zoom.ZoomDaemon.plist"),
    )
    .unwrap();
    file(root, "Library/PrivilegedHelperTools/us.zoom.ZoomDaemon", 16);
    file(root, "Library/LaunchDaemons/com.other.daemon.plist", 1);
    (home, bundle)
}

fn zoom_app(idx: &Index, bundle: &Path) -> AppInfo {
    app(
        idx,
        bundle,
        "us.zoom.xos",
        AppSource::Pkg {
            pkg_ids: vec!["us.zoom.pkg.videomeeting".into()],
        },
        LastUsed::Spotlight(NOW - DAY),
    )
}

#[test]
fn name_match_is_exact_only() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let (home, bundle) = zoom_tree(root);
    let idx = scan(root);
    let found = Ctx::new(root).run(&idx, &home, &[zoom_app(&idx, &bundle)], &mut HashSet::new());
    let z = found.iter().find(|f| f.title == "zoom.us").unwrap();
    let paths = component_paths(z);
    assert!(paths.contains(&home.join("Library/Application Support/zoom.us")));
    assert!(paths.contains(&home.join("Library/Logs/zoom.us")));
    assert!(paths.contains(&home.join("Library/Caches/us.zoom.xos")));
    assert!(
        !paths.contains(&home.join("Library/Logs/LogiZoomBridge")),
        "substring of the name is not a match"
    );
    assert!(!paths.contains(&home.join("Library/Application Support/ZoomUpdater")));
    assert_eq!(z.subtitle.as_deref(), Some("pkg · last opened yesterday"));
    // The pkg receipt is a component, forgotten with pkgutil.
    let r = z
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::Receipt)
        .unwrap();
    assert_eq!(
        r.removal,
        ComponentRemoval::PkgForget {
            pkg_id: "us.zoom.pkg.videomeeting".into()
        }
    );
    // LogiZoomBridge is not a bundle id either: no leftover group.
    assert!(
        !found.iter().any(|f| f.rule_id == "app-leftovers"),
        "{found:#?}"
    );
}

#[test]
fn launchd_label_reads_label_and_associated_ids() {
    let (label, assoc) =
        launchd_label(&Path::new(FIXTURES).join("us.zoom.ZoomDaemon.plist")).expect("label");
    assert_eq!(label, "us.zoom.ZoomDaemon");
    assert_eq!(assoc, vec!["us.zoom.xos".to_string()]);
    assert_eq!(launchd_label(&Path::new(FIXTURES).join("casks.json")), None);

    // The daemon attaches to Zoom through AssociatedBundleIdentifiers, its helper through
    // the daemon's label; both are system-level.
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let (home, bundle) = zoom_tree(root);
    let idx = scan(root);
    let found = Ctx::new(root).run(&idx, &home, &[zoom_app(&idx, &bundle)], &mut HashSet::new());
    let z = found.iter().find(|f| f.title == "zoom.us").unwrap();
    let daemon = component(
        z,
        &root.join("Library/LaunchDaemons/us.zoom.ZoomDaemon.plist"),
    );
    assert_eq!(daemon.kind, ComponentKind::LaunchDaemon);
    assert_eq!(daemon.title, "LaunchDaemon", "not loaded: no '· active'");
    assert_eq!(
        daemon.removal,
        ComponentRemoval::Bootout {
            label: "us.zoom.ZoomDaemon".into(),
            system: true
        }
    );
    assert_eq!(daemon.note.as_deref(), Some("needs administrator password"));
    assert!(daemon.default_on);
    let helper = component(
        z,
        &root.join("Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"),
    );
    assert_eq!(helper.kind, ComponentKind::PrivilegedHelper);
    assert!(
        !component_paths(z).contains(&root.join("Library/LaunchDaemons/com.other.daemon.plist"))
    );
    assert_eq!(z.label, SafetyLabel::NeedsPassword, "a daemon is selected");
}

#[test]
fn running_app_gets_app_running_label() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let bundle = root.join("Applications/Raycast.app");
    make_app(&bundle, "com.raycast.macos");
    let idx = scan(root);
    let mut ctx = Ctx::new(root);
    ctx.running.insert("com.raycast.macos".into());
    let apps = [app(
        &idx,
        &bundle,
        "com.raycast.macos",
        AppSource::Dragged,
        LastUsed::Spotlight(NOW),
    )];
    let found = ctx.run(&idx, &home, &apps, &mut HashSet::new());
    let f = &found[0];
    assert_eq!(f.label, SafetyLabel::AppRunning);
    assert!(f.flags.iter().any(|x| x == "app-running"));
    assert_eq!(
        f.subtitle.as_deref(),
        Some("drag & drop · last opened today")
    );
}

#[test]
fn leftover_group_for_removed_app_claims_its_nodes() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let bundle = root.join("Applications/Raycast.app");
    make_app(&bundle, "com.raycast.macos");
    let support = blob(
        &home,
        "Library/Application Support/com.bitwarden.desktop",
        2048,
    );
    let caches = blob(&home, "Library/Caches/com.bitwarden.desktop", 1536);
    let http = blob(&home, "Library/HTTPStorages/com.bitwarden.desktop", 8);
    let prefs = file(&home, "Library/Preferences/com.bitwarden.desktop.plist", 4);
    // Not leftovers of a removed app: Apple, a running app's vendor, a system app's vendor,
    // the installed app's own vendor.
    blob(&home, "Library/Caches/com.apple.Safari", 1536);
    blob(&home, "Library/Caches/com.tinyspeck.slackmacgap", 1536);
    blob(&home, "Library/Caches/org.example.systemapp.helper", 1536);
    blob(&home, "Library/Caches/com.raycast.shared", 1536);
    // Not bundle ids, Apple's own (team + `groups.`, Shortcuts), an installed app's name
    // under another vendor.
    file(&home, "Library/Application Support/copyq.log.1", 4);
    file(&home, "Library/Logs/warp.log.old.2", 4);
    blob(
        &home,
        "Library/Group Containers/243LU875E5.groups.com.apple.podcasts",
        8,
    );
    blob(
        &home,
        "Library/Group Containers/group.is.workflow.shortcuts",
        8,
    );
    file(
        &home,
        "Library/Preferences/org.amneziavpn.AmneziaVPN.plist",
        4,
    );
    let idx = scan(root);

    let mut ctx = Ctx::new(root);
    ctx.running.insert("com.tinyspeck.slackmacgap".into());
    ctx.other
        .insert("org.example.systemapp".into(), "System App".into());
    ctx.other
        .insert("org.amnezia.AmneziaVPN".into(), "AmneziaVPN".into());
    let apps = [app(
        &idx,
        &bundle,
        "com.raycast.macos",
        AppSource::Dragged,
        LastUsed::Spotlight(NOW),
    )];
    let mut claimed = HashSet::new();
    let found = ctx.run(&idx, &home, &apps, &mut claimed);
    let groups: Vec<&Finding> = found
        .iter()
        .filter(|f| f.rule_id == "app-leftovers")
        .collect();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    let g = groups[0];
    assert_eq!(g.id, FindingId::new("app-leftovers", "com.bitwarden"));
    assert_eq!(g.category, Category::Apps);
    assert_eq!(g.title, "Bitwarden");
    assert_eq!(
        g.subtitle.as_deref(),
        Some("leftovers of a removed app · 4 items")
    );
    assert_eq!(g.label, SafetyLabel::AppData);
    assert_eq!(g.explain, "No installed app found that uses these files.");
    assert_eq!(g.components.len(), 4);
    let Removal::Trash { paths } = &g.removal else {
        panic!("{:?}", g.removal)
    };
    for p in [&support, &caches, &http] {
        assert!(paths.contains(p), "{p:?}");
    }
    assert!(
        !paths.contains(&prefs),
        "settings go through defaults delete"
    );
    assert_eq!(
        component(g, &prefs).removal,
        ComponentRemoval::Defaults {
            domain: "com.bitwarden.desktop".into()
        }
    );
    assert!(g.allocated >= (2048 + 1536) * 1024);

    for p in [&support, &caches, &http, &prefs] {
        assert!(claimed.contains(&idx.find(p).unwrap()), "{p:?} claimed");
    }
    let caches_found = app_caches::find(&idx, &home, &mut claimed);
    for p in [&support, &caches] {
        assert!(
            !caches_found
                .iter()
                .any(|f| f.path.as_deref() == Some(p.as_path())),
            "{p:?} listed twice"
        );
    }
    assert!(
        caches_found
            .iter()
            .any(|f| f.path.as_deref() == Some(&*home.join("Library/Caches/com.apple.Safari")))
    );
}

#[test]
fn orphan_receipts_become_one_finding() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let idx = scan(root);
    let mut ctx = Ctx::new(root);
    let receipt = |id: &str, files: &[&str]| PkgReceipt {
        id: id.into(),
        version: "1".into(),
        volume: "/".into(),
        location: "Applications".into(),
        install_time: Some(NOW - 400 * DAY),
        files: files.iter().map(PathBuf::from).collect(),
    };
    ctx.receipts = vec![
        receipt(
            "com.bitwarden.desktop",
            &["/Applications/Discky Test Gone.app/Contents/Info.plist"],
        ),
        receipt("com.example.driver", &["/Library/Extensions/x.kext"]),
    ];
    let found = ctx.run(&idx, &home, &[], &mut HashSet::new());
    let r: Vec<&Finding> = found
        .iter()
        .filter(|f| f.rule_id == "pkg-receipts")
        .collect();
    assert_eq!(r.len(), 1, "{found:#?}");
    let r = r[0];
    assert_eq!(r.id, FindingId::new("pkg-receipts", "orphans"));
    assert_eq!(r.title, "Package receipts of removed apps");
    assert_eq!(r.category, Category::Apps);
    assert_eq!(r.allocated, 0);
    assert_eq!(r.components.len(), 1);
    let c = &r.components[0];
    assert_eq!(c.kind, ComponentKind::Receipt);
    assert!(c.default_on);
    assert_eq!(
        c.removal,
        ComponentRemoval::PkgForget {
            pkg_id: "com.bitwarden.desktop".into()
        }
    );

    // No orphans → no finding.
    ctx.receipts.clear();
    let found = ctx.run(&idx, &home, &[], &mut HashSet::new());
    assert!(!found.iter().any(|f| f.rule_id == "pkg-receipts"));
}

/// Read-only: inventory + findings on this Mac (brew/pkgutil/mdfind/lsappinfo/launchctl
/// print are asked; nothing is changed). Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn apps_findings_on_this_mac() {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let roots: Vec<PathBuf> = [
        PathBuf::from("/Applications"),
        home.join("Applications"),
        home.join("Library"),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/Library/Application Support"),
        PathBuf::from("/Library/PrivilegedHelperTools"),
        PathBuf::from("/Library/Preferences"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect();
    let started = std::time::Instant::now();
    let idx = walk(
        &ScanOptions {
            roots,
            exclude: globset::GlobSet::empty(),
            threads: 0,
            exact_private_size: false,
            cancel: None,
        },
        &|_| {},
    );
    let walked = started.elapsed();
    let running = discky_core::tools::running_app_bundle_ids();
    let started = std::time::Instant::now();
    let found = discky_core::findings::apps::find(&idx, &home, &mut HashSet::new(), &running);
    let took = started.elapsed();
    let apps = found.iter().filter(|f| f.rule_id == "apps").count();
    let groups: Vec<&Finding> = found
        .iter()
        .filter(|f| f.rule_id == "app-leftovers")
        .collect();
    let receipts = found.iter().filter(|f| f.rule_id == "pkg-receipts").count();
    println!("walk {walked:?}, apps::find {took:?}");
    println!(
        "apps {apps}, leftover groups {}, receipts findings {receipts}",
        groups.len()
    );
    for f in found.iter().filter(|f| f.rule_id == "apps") {
        println!(
            "  {:<28} {:>12} {:?} {} comps",
            f.title,
            f.allocated,
            f.subtitle,
            f.components.len()
        );
        if std::env::var_os("DISCKY_VERBOSE").is_some() {
            for c in &f.components {
                println!(
                    "      {:<22} {:>12} on={} {:?} {:?} {:?}",
                    c.title, c.allocated, c.default_on, c.removal, c.note, c.path
                );
            }
        }
    }
    for g in &groups {
        println!(
            "  [group] {:<24} {:>12} {:?}",
            g.title, g.allocated, g.subtitle
        );
        for c in g.components.iter().take(3) {
            println!("      {:?}", c.path);
        }
    }
}

#[test]
fn tiny_leftover_groups_are_dropped() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let bundle = root.join("Applications/Raycast.app");
    make_app(&bundle, "com.raycast.macos");
    // Below both thresholds: one small item, two small items.
    let tiny = file(&home, "Library/Preferences/com.tiny.app.plist", 4);
    file(&home, "Library/Preferences/com.pair.app.plist", 4);
    let pair_cache = blob(&home, "Library/Caches/com.pair.app", 8);
    // Three small items: shown.
    file(&home, "Library/Preferences/com.three.app.plist", 4);
    blob(&home, "Library/Caches/com.three.app", 8);
    blob(&home, "Library/HTTPStorages/com.three.app", 8);
    // One big item: shown.
    blob(&home, "Library/Application Support/com.big.app", 1024);
    let idx = scan(root);
    let apps = [app(
        &idx,
        &bundle,
        "com.raycast.macos",
        AppSource::Dragged,
        LastUsed::Spotlight(NOW),
    )];
    let mut claimed = HashSet::new();
    let found = Ctx::new(root).run(&idx, &home, &apps, &mut claimed);
    let mut ids: Vec<FindingId> = found
        .iter()
        .filter(|f| f.rule_id == "app-leftovers")
        .map(|f| f.id.clone())
        .collect();
    ids.sort_by(|a, b| a.0.cmp(&b.0));
    let mut want = vec![
        FindingId::new("app-leftovers", "com.three"),
        FindingId::new("app-leftovers", "com.big"),
    ];
    want.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ids, want, "{found:#?}");
    for p in [&tiny, &pair_cache] {
        assert!(
            !claimed.contains(&idx.find(p).unwrap()),
            "{p:?}: dropped groups claim nothing"
        );
    }
}

#[test]
fn zap_paths_mark_components_as_covered() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let bundle = root.join("Applications/Hex.app");
    make_app(&bundle, "com.example.hex");
    let zapped = blob(&home, "Library/Application Support/com.example.hex", 64);
    let cache = blob(&home, "Library/Caches/com.example.hex", 8);
    let under = blob(&home, "Library/Logs/Hex", 8);
    let config = blob(&home, ".config/hex", 8);
    let not_zapped = file(&home, "Library/Preferences/com.example.hex.plist", 4);
    let idx = scan(root);
    let mut ctx = Ctx::new(root);
    ctx.casks = vec![Cask {
        token: "hex".into(),
        full_token: "anomalyco/tap/hex".into(),
        installed: Some("1".into()),
        app_targets: vec![bundle.clone()],
        uninstall: Vec::new(),
        zap: vec![Directive {
            trash: vec!["~/Library/Application Support/com.example.hex".into()],
            // A whole location folder: never a component itself, but what lies under it
            // is covered.
            delete: vec!["~/.config/hex".into(), "~/Library/Logs".into()],
            // rmdir removes an empty folder only: exactly this path is covered.
            rmdir: vec![
                "~/Library/Caches/com.example.hex".into(),
                "~/Library/Preferences".into(),
            ],
            ..Default::default()
        }],
    }];
    let cask_app = app(
        &idx,
        &bundle,
        "com.example.hex",
        AppSource::Cask {
            token: "hex".into(),
            full_token: "anomalyco/tap/hex".into(),
        },
        LastUsed::Spotlight(NOW),
    );
    let found = ctx.run(&idx, &home, &[cask_app], &mut HashSet::new());
    let f = found.iter().find(|f| f.title == "Hex").unwrap();
    assert_eq!(f.components[0].kind, ComponentKind::AppBundle);
    assert!(f.components[0].covered_by_cask, "the bundle of a cask app");
    for p in [&zapped, &cache, &under, &config] {
        assert!(component(f, p).covered_by_cask, "{p:?}");
    }
    assert!(
        !component(f, &not_zapped).covered_by_cask,
        "under an rmdir path is not covered"
    );
    for p in ["Library/Logs", "Library/Preferences"] {
        assert!(
            !component_paths(f).contains(&home.join(p)),
            "{p}: a location folder is never a component"
        );
    }
    assert!(
        !f.components.last().unwrap().covered_by_cask,
        "Keychain line"
    );
    assert!(
        !f.flags.iter().any(|x| x == "zap-shared"),
        "no shared zap path: {:?}",
        f.flags
    );

    // A dragged app: nothing is covered.
    let found = Ctx::new(root).run(
        &idx,
        &home,
        &[app(
            &idx,
            &bundle,
            "com.example.hex",
            AppSource::Dragged,
            LastUsed::Spotlight(NOW),
        )],
        &mut HashSet::new(),
    );
    assert!(found[0].components.iter().all(|c| !c.covered_by_cask));
}

/// A launchd plist at `path` with `Label`, `AssociatedBundleIdentifiers` and `Program`.
fn launchd_plist(path: &Path, label: &str, associated: &[&str], program: Option<&Path>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut d = plist::Dictionary::new();
    d.insert("Label".into(), label.into());
    if !associated.is_empty() {
        d.insert(
            "AssociatedBundleIdentifiers".into(),
            plist::Value::Array(associated.iter().map(|a| (*a).into()).collect()),
        );
    }
    if let Some(p) = program {
        d.insert("Program".into(), p.to_string_lossy().into_owned().into());
    }
    plist::Value::Dictionary(d).to_file_xml(path).unwrap();
}

#[test]
fn job_associated_with_two_installed_apps_is_shared() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let one = root.join("Applications/One.app");
    make_app(&one, "com.alpha.one");
    let two = root.join("Applications/Two.app");
    make_app(&two, "com.beta.two");
    let helper = file(root, "Library/PrivilegedHelperTools/org.gamma.updater", 16);
    let daemon = root.join("Library/LaunchDaemons/org.gamma.updater.plist");
    launchd_plist(
        &daemon,
        "org.gamma.updater",
        &["com.alpha.one", "com.beta.two"],
        Some(&helper),
    );
    // Associated with one app and a running helper process that is no installed bundle:
    // attached normally.
    let solo = root.join("Library/LaunchAgents/org.gamma.solo.plist");
    launchd_plist(
        &solo,
        "org.gamma.solo",
        &["com.alpha.one", "com.alpha.helperprocess"],
        None,
    );
    let idx = scan(root);
    let apps = [
        app(
            &idx,
            &one,
            "com.alpha.one",
            AppSource::Dragged,
            LastUsed::Spotlight(NOW),
        ),
        app(
            &idx,
            &two,
            "com.beta.two",
            AppSource::Dragged,
            LastUsed::Spotlight(NOW),
        ),
    ];
    let mut ctx = Ctx::new(root);
    ctx.running.insert("com.alpha.helperprocess".into());
    let found = ctx.run(&idx, &home, &apps, &mut HashSet::new());
    for (title, other) in [("One", "Two"), ("Two", "One")] {
        let f = found.iter().find(|f| f.title == title).unwrap();
        for p in [&daemon, &helper] {
            let c = component(f, p);
            assert_eq!(c.removal, ComponentRemoval::None, "{title} {p:?}");
            assert!(!c.default_on, "{title} {p:?}");
            assert_eq!(c.note.as_deref(), Some(&*format!("shared with {other}")));
        }
        if title == "Two" {
            // One's own /Library agent needs a password; Two has only shared system items.
            assert_eq!(
                f.label,
                SafetyLabel::AppData,
                "the shared daemon is not selected"
            );
        }
    }
    let f = found.iter().find(|f| f.title == "One").unwrap();
    let c = component(f, &solo);
    assert!(c.default_on);
    assert_eq!(
        c.removal,
        ComponentRemoval::Bootout {
            label: "org.gamma.solo".into(),
            system: false
        }
    );
}

#[test]
fn cask_launchctl_label_of_a_shared_vendor_is_shared() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let home = root.join("home");
    let chrome = root.join("Applications/Google Chrome.app");
    make_app(&chrome, "com.google.Chrome");
    let drive = root.join("Applications/Google Drive.app");
    make_app(&drive, "com.google.drivefs");
    let agent = home.join("Library/LaunchAgents/com.google.keystone.agent.plist");
    launchd_plist(&agent, "com.google.keystone.agent", &[], None);
    let own_agent = home.join("Library/LaunchAgents/com.google.Chrome.updater.plist");
    launchd_plist(&own_agent, "com.google.Chrome.updater", &[], None);
    let idx = scan(root);
    let mut ctx = Ctx::new(root);
    ctx.casks = vec![Cask {
        token: "google-chrome".into(),
        full_token: "google-chrome".into(),
        installed: Some("1".into()),
        app_targets: vec![chrome.clone()],
        uninstall: vec![Directive {
            launchctl: vec!["com.google.keystone.agent".into()],
            ..Default::default()
        }],
        zap: Vec::new(),
    }];
    let apps = [
        app(
            &idx,
            &chrome,
            "com.google.Chrome",
            AppSource::Cask {
                token: "google-chrome".into(),
                full_token: "google-chrome".into(),
            },
            LastUsed::Spotlight(NOW),
        ),
        app(
            &idx,
            &drive,
            "com.google.drivefs",
            AppSource::Dragged,
            LastUsed::Spotlight(NOW),
        ),
    ];
    let found = ctx.run(&idx, &home, &apps, &mut HashSet::new());
    let c = found.iter().find(|f| f.title == "Google Chrome").unwrap();
    let a = component(c, &agent);
    assert_eq!(a.removal, ComponentRemoval::None);
    assert!(!a.default_on);
    assert_eq!(a.note.as_deref(), Some("shared with Google Drive"));
    let own = component(c, &own_agent);
    assert!(own.default_on, "label has Chrome's bundle id as prefix");
    assert!(matches!(own.removal, ComponentRemoval::Bootout { .. }));
}
