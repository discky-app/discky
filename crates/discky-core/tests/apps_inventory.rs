//! App inventory: bundle enumeration, Info.plist, cask / pkg / Spotlight parsing.
//! Nothing here runs an external command (tool paths are `None`, outputs are fixtures).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use discky_core::findings::AppSource;
use discky_core::findings::apps::cask::{
    Script, cask_for_bundle, expand_zap_path, installed_zap, parse_casks, read_caskroom,
};
use discky_core::findings::apps::inventory::{app_bundles, app_bundles_in, read_bundle};
use discky_core::findings::apps::last_used::{estimate_from, parse_mdfind_line, resolve};
use discky_core::findings::apps::pkg::{
    PkgReceipt, orphan_receipts, parse_pkg_info, pkgs_for_bundle,
};
use discky_core::findings::apps::{LastUsed, ToolPaths, assemble, inventory};
use discky_core::fs::walk::{ScanOptions, walk};
use discky_core::index::Index;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/apps");

fn fixture(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURES).join(name)).unwrap()
}

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

/// An `.app` directory with an Info.plist built from `keys` (string values, plus
/// `LSUIElement` as a boolean when present).
fn make_app(path: &Path, keys: &[(&str, &str)]) {
    let contents = path.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    let mut dict = plist::Dictionary::new();
    for (k, v) in keys {
        let value = if *k == "LSUIElement" {
            plist::Value::Boolean(*v == "true")
        } else {
            plist::Value::String(v.to_string())
        };
        dict.insert(k.to_string(), value);
    }
    plist::Value::Dictionary(dict)
        .to_file_xml(contents.join("Info.plist"))
        .unwrap();
    std::fs::write(contents.join("MacOS/bin"), b"x").unwrap();
}

fn receipt(id: &str, files: &[&str]) -> PkgReceipt {
    PkgReceipt {
        id: id.into(),
        version: "1".into(),
        volume: "/".into(),
        location: "Applications".into(),
        install_time: None,
        files: files.iter().map(PathBuf::from).collect(),
    }
}

#[test]
fn parse_casks_handles_string_or_array_directives() {
    let casks = parse_casks(&fixture("casks.json")).unwrap();
    assert_eq!(casks.len(), 5);

    let raycast = &casks[0];
    assert_eq!(raycast.token, "raycast");
    assert_eq!(raycast.installed.as_deref(), Some("2.9.0.0"));
    assert_eq!(
        raycast.app_targets,
        vec![PathBuf::from("/Applications/Raycast.app")]
    );
    assert_eq!(raycast.uninstall[0].quit, vec!["com.raycast.macos"]);
    assert_eq!(raycast.uninstall[0].login_item, vec!["Raycast"]);
    assert_eq!(raycast.zap[0].trash.len(), 6);

    let hex = &casks[1];
    assert_eq!(hex.full_token, "anomalyco/tap/hex");

    let zoom = &casks[2];
    assert_eq!(zoom.installed, None);
    assert!(zoom.app_targets.is_empty());
    let u = &zoom.uninstall[0];
    assert_eq!(u.launchctl.len(), 3);
    assert_eq!(
        u.signal,
        vec![("KILL".to_string(), "us.zoom.xos".to_string())]
    );
    assert_eq!(u.pkgutil, vec!["us.zoom.pkg.videomeeting"]); // a bare string
    assert_eq!(u.delete.len(), 4); // an array
    assert_eq!(zoom.zap[0].delete, vec!["/Library/Logs/zoomusinstall.log"]); // a bare string

    let tv = &casks[3];
    assert_eq!(tv.uninstall[0].quit.len(), 2);
    assert_eq!(tv.uninstall[0].pkgutil.len(), 3);

    let adobe = &casks[4];
    let a = &adobe.uninstall[0];
    assert_eq!(
        a.script,
        Some(Script {
            executable: "/usr/bin/pkill".into(),
            args: vec![
                "Adobe Desktop Service".into(),
                "AdobeIPCBroker".into(),
                "AdobeCRDaemon".into()
            ],
            must_succeed: false,
            sudo: false,
        })
    );
    assert_eq!(
        a.early_script.as_ref().map(|s| s.executable.as_str()),
        Some("/usr/bin/pluginkit")
    );
    assert_eq!(a.rmdir.len(), 2);
    assert_eq!(
        adobe.zap[0].rmdir,
        vec!["~/Library/Application Support/Adobe"]
    );

    assert!(parse_casks("not json").is_err());
    assert_eq!(
        parse_casks(r#"{"formulae":[],"casks":[]}"#).unwrap(),
        vec![]
    );
}

#[test]
fn expand_zap_path_expands_tilde_braces_and_globs() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let prefs = home.join("Library/Preferences");
    std::fs::create_dir_all(&prefs).unwrap();
    for f in [
        "us.zoom.xos.plist",
        "us.zoom.updater.plist",
        "ZoomChat.plist",
        "other.plist",
    ] {
        std::fs::write(prefs.join(f), b"").unwrap();
    }
    let groups = home.join("Library/Group Containers");
    std::fs::create_dir_all(groups.join("BJ4HAAB9B3.ZoomClient3rd")).unwrap();
    let adobe = tmp.path().join("Adobe");
    std::fs::create_dir_all(adobe.join("CEP/extensions")).unwrap();

    assert_eq!(
        expand_zap_path("~/Library/Preferences/us.zoom.*.plist", &home),
        vec![
            prefs.join("us.zoom.updater.plist"),
            prefs.join("us.zoom.xos.plist")
        ]
    );
    assert_eq!(
        expand_zap_path("~/Library/Group Containers/*.ZoomClient3rd", &home),
        vec![groups.join("BJ4HAAB9B3.ZoomClient3rd")]
    );
    assert_eq!(
        expand_zap_path("~/Library/Preferences/ZoomChat.plist", &home),
        vec![prefs.join("ZoomChat.plist")]
    );
    // Missing paths are dropped.
    assert!(expand_zap_path("~/.zoomus", &home).is_empty());
    // Nested braces: Adobe, Adobe/CEP, Adobe/CEP/extensions.
    let pattern = format!("{}{{/CEP{{/extensions,}},}}", adobe.display());
    assert_eq!(
        expand_zap_path(&pattern, &home),
        vec![
            adobe.clone(),
            adobe.join("CEP"),
            adobe.join("CEP/extensions")
        ]
    );
    // A glob in a middle segment.
    let pattern = format!("{}/*/extensions", adobe.display());
    assert_eq!(
        expand_zap_path(&pattern, &home),
        vec![adobe.join("CEP/extensions")]
    );
}

#[test]
fn cask_for_bundle_matches_app_target() {
    let casks = parse_casks(&fixture("casks.json")).unwrap();
    let c = cask_for_bundle(&casks, Path::new("/Applications/Raycast.app")).unwrap();
    assert_eq!(c.token, "raycast");
    assert_eq!(
        cask_for_bundle(&casks, Path::new("/Applications/Hex.app")).map(|c| c.token.as_str()),
        Some("hex")
    );
    assert!(cask_for_bundle(&casks, Path::new("/Applications/Slack.app")).is_none());
    // Not-installed casks never claim a bundle.
    assert!(cask_for_bundle(&casks, Path::new("/Applications/zoom.us.app")).is_none());
}

#[test]
fn offline_caskroom_reads_cached_definition_or_install_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    let room = tmp.path().join("Caskroom");
    let apps = tmp.path().join("Applications");
    std::fs::create_dir_all(apps.join("Raycast.app")).unwrap();
    std::fs::create_dir_all(apps.join("Hex.app")).unwrap();

    // raycast: an empty cached definition (as on the research machine) → INSTALL_RECEIPT.
    let rc = room.join("raycast");
    std::fs::create_dir_all(rc.join("2.9.0.0")).unwrap();
    std::os::unix::fs::symlink(apps.join("Raycast.app"), rc.join("2.9.0.0/Raycast.app")).unwrap();
    std::fs::create_dir_all(rc.join(".metadata/2.9.0.0/20261026211914.361/Casks")).unwrap();
    std::fs::write(
        rc.join(".metadata/2.9.0.0/20261026211914.361/Casks/raycast.json"),
        "{}",
    )
    .unwrap();
    std::fs::write(
        rc.join(".metadata/INSTALL_RECEIPT.json"),
        r#"{"source":{"tap":"homebrew/cask","version":"2.9.0.0"},
            "uninstall_artifacts":[{"uninstall":[{"quit":"com.raycast.macos"}]},
            {"app":["Raycast.app"]},{"zap":[{"trash":["~/.config/raycast"]}]}]}"#,
    )
    .unwrap();

    // hex: two cached definitions; the newest timestamp directory wins.
    let hx = room.join("hex");
    std::fs::create_dir_all(hx.join("3.2.0")).unwrap();
    std::os::unix::fs::symlink(apps.join("Hex.app"), hx.join("3.2.0/Hex.app")).unwrap();
    for (ts, quit) in [
        ("20250101000000.000", "old.hex"),
        ("20261102160300.100", "anomaly.hex"),
    ] {
        let d = hx.join(format!(".metadata/3.2.0/{ts}/Casks"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("hex.json"),
            format!(
                r#"{{"token":"hex","full_token":"anomalyco/tap/hex","artifacts":[{{"uninstall":[{{"quit":"{quit}"}}]}}]}}"#
            ),
        )
        .unwrap();
    }

    let casks = read_caskroom(&room, None);
    assert_eq!(casks.len(), 2);
    let hex = casks.iter().find(|c| c.token == "hex").unwrap();
    assert_eq!(hex.full_token, "anomalyco/tap/hex");
    assert_eq!(hex.installed.as_deref(), Some("3.2.0"));
    assert_eq!(hex.uninstall[0].quit, vec!["anomaly.hex"]);
    assert_eq!(
        cask_for_bundle(&casks, &apps.join("Hex.app")).map(|c| c.token.as_str()),
        Some("hex")
    );
    let ray = casks.iter().find(|c| c.token == "raycast").unwrap();
    assert_eq!(ray.full_token, "raycast");
    assert_eq!(ray.uninstall[0].quit, vec!["com.raycast.macos"]);
    assert_eq!(ray.zap[0].trash, vec!["~/.config/raycast"]);
    assert_eq!(
        cask_for_bundle(&casks, &apps.join("Raycast.app")).map(|c| c.token.as_str()),
        Some("raycast")
    );
    // A token list limits what is read.
    assert_eq!(read_caskroom(&room, Some(&["hex".to_string()])).len(), 1);
    assert!(read_caskroom(&tmp.path().join("nope"), None).is_empty());
}

#[test]
fn parse_pkg_info_reads_location_and_time() {
    let (id, version, volume, location, time) =
        parse_pkg_info(&fixture("zoom.pkg-info.txt")).unwrap();
    assert_eq!(id, "us.zoom.pkg.videomeeting");
    assert_eq!(version, "6.6.10.69071");
    assert_eq!(volume, PathBuf::from("/"));
    assert_eq!(location, PathBuf::from("Applications"));
    assert_eq!(time, Some(1769687254));

    let (id, _, _, location, _) = parse_pkg_info(&fixture("karabiner.pkg-info.txt")).unwrap();
    assert_eq!(id, "org.pqrs.Karabiner-Elements");
    assert_eq!(location, PathBuf::new());

    assert!(parse_pkg_info("garbage\n").is_none());
}

#[test]
fn pkgs_for_bundle_matches_files_under_bundle() {
    let receipts = vec![
        receipt(
            "us.zoom.pkg.videomeeting",
            &[
                "/Applications/zoom.us.app",
                "/Applications/zoom.us.app/Contents",
            ],
        ),
        receipt(
            "com.tailscale.ipn.macsys",
            &["/Applications/Tailscale.app/Contents/Info.plist"],
        ),
        receipt(
            "com.google.Keystone",
            &["/Library/Google/GoogleSoftwareUpdate"],
        ),
        receipt("com.zoomish", &["/Applications/zoom.us.application/x"]),
    ];
    let ids = |b: &str| -> Vec<String> {
        pkgs_for_bundle(&receipts, Path::new(b))
            .iter()
            .map(|r| r.id.clone())
            .collect()
    };
    assert_eq!(
        ids("/Applications/zoom.us.app"),
        vec!["us.zoom.pkg.videomeeting"]
    );
    assert_eq!(
        ids("/Applications/Tailscale.app"),
        vec!["com.tailscale.ipn.macsys"]
    );
    assert!(ids("/Applications/Slack.app").is_empty());
}

#[test]
fn orphan_receipts_detects_missing_apps() {
    let receipts = vec![
        receipt(
            "present",
            &[
                "/Applications/Present-x.app",
                "/Applications/Present-x.app/Contents",
            ],
        ),
        receipt(
            "gone",
            &[
                "/Applications/Bitwarden-discky-test.app",
                "/Applications/Bitwarden-discky-test.app/Contents",
            ],
        ),
        receipt(
            "in-subfolder-gone",
            &["/Applications/Vendor/Gone-discky-test.app/Contents/Info.plist"],
        ),
        receipt("no-apps", &["/Library/Google/GoogleSoftwareUpdate"]),
    ];
    let installed: HashSet<PathBuf> = [PathBuf::from("/Applications/Present-x.app")].into();
    let ids: Vec<&str> = orphan_receipts(&receipts, &installed)
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(ids, vec!["gone", "in-subfolder-gone"]);
}

#[test]
fn parse_mdfind_line_reads_path_and_date() {
    let text = fixture("mdfind.txt");
    let parsed: Vec<_> = text.lines().filter_map(parse_mdfind_line).collect();
    assert_eq!(parsed.len(), 4); // the `(null)` line is skipped
    assert_eq!(
        parsed[2],
        (PathBuf::from("/Applications/Google Chrome.app"), 1793709310)
    );
    assert_eq!(
        parsed[3],
        (PathBuf::from("/Applications/Slack.app"), 1793709308)
    );
    assert_eq!(parse_mdfind_line(""), None);
    assert_eq!(parse_mdfind_line("/Applications/X.app"), None);
}

#[test]
fn last_used_unknown_falls_back_to_leftovers_with_estimate_flag() {
    assert_eq!(estimate_from(&[]), LastUsed::Unknown);
    assert_eq!(estimate_from(&[10, 30, 20]), LastUsed::Estimated(30));
    assert_eq!(resolve(Some(5), &[10]), LastUsed::Spotlight(5));
    assert_eq!(resolve(None, &[10, 7]), LastUsed::Estimated(10));
    assert_eq!(resolve(None, &[]), LastUsed::Unknown);
    assert_eq!(
        serde_json::to_string(&LastUsed::Estimated(3)).unwrap(),
        r#"{"estimated":3}"#
    );
}

#[test]
fn app_bundles_skips_symlinks_nested_and_system() {
    let tmp = tempfile::tempdir().unwrap();
    let apps = tmp.path().join("Applications");
    let home = tmp.path().join("home");
    make_app(&apps.join("A.app"), &[]);
    make_app(&apps.join("A.app/Contents/Frameworks/B.app"), &[]);
    std::os::unix::fs::symlink("A.app", apps.join("S.app")).unwrap();
    make_app(&apps.join("Adobe/Photoshop.app"), &[]);
    make_app(&apps.join("Adobe/Deep/TooDeep.app"), &[]);
    std::fs::create_dir_all(apps.join("NotAnApp")).unwrap();
    make_app(&home.join("Applications/U.app"), &[]);
    make_app(&home.join("Applications/Sub/V.app"), &[]);
    let index = scan(tmp.path());

    let found: Vec<PathBuf> = app_bundles_in(&index, &apps, &home.join("Applications"))
        .into_iter()
        .map(|(id, p)| {
            assert_eq!(index.path(id), p);
            p
        })
        .collect();
    assert_eq!(
        found,
        vec![
            apps.join("A.app"),
            apps.join("Adobe/Photoshop.app"),
            home.join("Applications/U.app"),
        ]
    );
    // The real entry point: `/Applications` is not in this index, `~/Applications` is.
    let found: Vec<PathBuf> = app_bundles(&index, &home)
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    assert_eq!(found, vec![home.join("Applications/U.app")]);
}

#[test]
fn read_bundle_reads_plist_and_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("Things3.app");
    make_app(
        &a,
        &[
            ("CFBundleIdentifier", "com.culturedcode.ThingsMac"),
            ("CFBundleName", "Things3"),
            ("CFBundleShortVersionString", "3.13.3"),
            ("LSUIElement", "true"),
        ],
    );
    std::fs::create_dir_all(a.join("Contents/_MASReceipt")).unwrap();
    std::fs::write(a.join("Contents/_MASReceipt/receipt"), b"").unwrap();
    std::fs::create_dir_all(a.join("Contents/Resources")).unwrap();
    std::fs::write(a.join("Contents/Resources/UninstallThingsCLI.scpt"), b"").unwrap();

    let m = read_bundle(&a);
    assert_eq!(m.bundle_id.as_deref(), Some("com.culturedcode.ThingsMac"));
    assert_eq!(m.name.as_deref(), Some("Things3"));
    assert_eq!(m.version.as_deref(), Some("3.13.3"));
    assert!(m.ui_element);
    assert!(m.mas_receipt);
    assert!(!m.root_owned);
    assert_eq!(
        m.own_uninstaller,
        Some(a.join("Contents/Resources/UninstallThingsCLI.scpt"))
    );

    // No plist keys, no receipt; a sibling "<Name> Uninstaller.app".
    let b = tmp.path().join("Bare.app");
    make_app(&b, &[]);
    make_app(&tmp.path().join("Bare Uninstaller.app"), &[]);
    let m = read_bundle(&b);
    assert_eq!(m.bundle_id, None);
    assert_eq!(m.version, None);
    assert!(!m.ui_element && !m.mas_receipt);
    assert_eq!(
        m.own_uninstaller,
        Some(tmp.path().join("Bare Uninstaller.app"))
    );

    // `Contents/MacOS`: a non-executable `uninstall_*.html` is not an uninstaller, an
    // executable `Uninstaller` is.
    let d = tmp.path().join("Amnezia.app");
    make_app(&d, &[]);
    std::fs::write(d.join("Contents/MacOS/uninstall_conclusion.html"), b"").unwrap();
    assert_eq!(read_bundle(&d).own_uninstaller, None);
    let exe = d.join("Contents/MacOS/Uninstaller");
    std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(read_bundle(&d).own_uninstaller, Some(exe));

    // No Info.plist at all.
    let c = tmp.path().join("Broken.app");
    std::fs::create_dir_all(&c).unwrap();
    let m = read_bundle(&c);
    assert_eq!(m.bundle_id, None);
    assert_eq!(m.own_uninstaller, None);
}

#[test]
fn assemble_picks_cask_then_pkg_then_app_store_then_dragged() {
    let tmp = tempfile::tempdir().unwrap();
    let apps = tmp.path().join("Applications");
    let home = tmp.path().join("home");
    make_app(
        &apps.join("Raycast.app"),
        &[
            ("CFBundleIdentifier", "com.raycast.macos"),
            ("CFBundleShortVersionString", "2.10.1.0"),
        ],
    );
    make_app(
        &apps.join("zoom.us.app"),
        &[("CFBundleIdentifier", "us.zoom.xos")],
    );
    make_app(&apps.join("Things3.app"), &[]);
    std::fs::create_dir_all(apps.join("Things3.app/Contents/_MASReceipt")).unwrap();
    make_app(&apps.join("Slack.app"), &[]);
    let index = scan(tmp.path());
    let bundles = app_bundles_in(&index, &apps, &home.join("Applications"));

    let mut casks = parse_casks(&fixture("casks.json")).unwrap();
    casks[0].app_targets = vec![apps.join("Raycast.app")];
    let receipts = vec![receipt(
        "us.zoom.pkg.videomeeting",
        &[apps.join("zoom.us.app").to_str().unwrap()],
    )];
    let spotlight: HashMap<PathBuf, i64> = [(apps.join("Slack.app"), 1793709308)].into();

    let infos = assemble(&bundles, &casks, &receipts, &spotlight);
    let by_name: HashMap<&str, _> = infos.iter().map(|i| (i.name.as_str(), i)).collect();
    assert_eq!(infos.len(), 4);
    assert_eq!(
        by_name["Raycast"].source,
        AppSource::Cask {
            token: "raycast".into(),
            full_token: "raycast".into()
        }
    );
    assert_eq!(by_name["Raycast"].version.as_deref(), Some("2.10.1.0")); // the bundle's, not brew's
    assert_eq!(
        by_name["Raycast"].bundle_id.as_deref(),
        Some("com.raycast.macos")
    );
    assert_eq!(
        by_name["zoom.us"].source,
        AppSource::Pkg {
            pkg_ids: vec!["us.zoom.pkg.videomeeting".into()]
        }
    );
    assert_eq!(by_name["Things3"].source, AppSource::AppStore);
    assert_eq!(by_name["Slack"].source, AppSource::Dragged);
    assert_eq!(by_name["Slack"].last_used, LastUsed::Spotlight(1793709308));
    assert_eq!(by_name["Things3"].last_used, LastUsed::Unknown);
    assert_eq!(
        by_name["Slack"].node,
        index.find(&apps.join("Slack.app")).unwrap()
    );

    // With no tools at all the inventory still works (all Dragged/AppStore, Unknown).
    let infos = inventory(&index, &home, &ToolPaths::default());
    assert!(infos.is_empty()); // `/Applications` is not in this index, `~/Applications` is empty
}

/// Read-only smoke run on this Mac: `cargo test -p discky-core --test apps_inventory -- --ignored --nocapture`.
#[test]
#[ignore]
fn inventory_on_this_mac() {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let mut roots = vec![PathBuf::from("/Applications")];
    if home.join("Applications").is_dir() {
        roots.push(home.join("Applications"));
    }
    let index = walk(
        &ScanOptions {
            roots,
            exclude: globset::GlobSet::empty(),
            threads: 0,
            exact_private_size: false,
            cancel: None,
        },
        &|_| {},
    );
    let tools = ToolPaths::detect();
    println!("tools: {tools:?}");
    let t = std::time::Instant::now();
    let infos = inventory(&index, &home, &tools);
    println!("inventory: {} apps in {:?}", infos.len(), t.elapsed());
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for i in &infos {
        let kind = match &i.source {
            AppSource::Cask { .. } => "cask",
            AppSource::Pkg { .. } => "pkg",
            AppSource::AppStore => "app_store",
            AppSource::Dragged => "dragged",
        };
        *counts.entry(kind).or_default() += 1;
        println!(
            "{:<28} {:<10} {:<40} root={} last={:?} uninstaller={:?} src={:?}",
            i.name,
            kind,
            i.bundle_id.as_deref().unwrap_or("-"),
            i.root_owned,
            i.last_used,
            i.own_uninstaller,
            i.source
        );
    }
    let spotlight = infos
        .iter()
        .filter(|i| matches!(i.last_used, LastUsed::Spotlight(_)))
        .count();
    println!(
        "sources: {counts:?}; spotlight last-used: {spotlight}/{}",
        infos.len()
    );
}

/// `<room>/<token>/.metadata/<ver>/<ts>/Casks/<file>` with `body`.
fn cached(room: &std::path::Path, token: &str, ts: &str, file: &str, body: &str) {
    let d = room.join(format!("{token}/.metadata/1.0/{ts}/Casks"));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(file), body).unwrap();
}

const ZAP_JSON: &str = r#"{"token":"x","artifacts":[{"zap":[{"trash":["~/Library/Caches/x"]}]}]}"#;

#[test]
fn rb_only_cask_metadata_disables_zap() {
    let tmp = tempfile::tempdir().unwrap();
    let room = tmp.path();
    cached(room, "x", "20260101000000.000", "x.rb", "cask \"x\" do end");
    assert_eq!(installed_zap(room, "x"), None);
    // The install receipt's uninstall_artifacts are what brew records; they count.
    std::fs::write(
        room.join("x/.metadata/INSTALL_RECEIPT.json"),
        r#"{"uninstall_artifacts":[{"zap":[{"trash":["~/a"]}]}]}"#,
    )
    .unwrap();
    let zap = installed_zap(room, "x").unwrap();
    assert_eq!(zap[0].trash, ["~/a"]);
    // A receipt without uninstall_artifacts does not.
    std::fs::write(room.join("x/.metadata/INSTALL_RECEIPT.json"), "{}").unwrap();
    assert_eq!(installed_zap(room, "x"), None);
    // No Caskroom entry at all.
    assert_eq!(installed_zap(room, "missing"), None);
}

#[test]
fn older_json_is_not_used_when_a_newer_dir_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let room = tmp.path();
    cached(room, "x", "20250101000000.000", "x.json", ZAP_JSON);
    assert_eq!(
        installed_zap(room, "x").unwrap()[0].trash,
        ["~/Library/Caches/x"]
    );
    cached(room, "x", "20260101000000.000", "x.rb", "cask \"x\" do end");
    assert_eq!(installed_zap(room, "x"), None);
    // A parseable JSON in the newest dir is used; a cask without zap is an empty stanza.
    cached(
        room,
        "x",
        "20270101000000.000",
        "x.json",
        r#"{"token":"x","artifacts":[]}"#,
    );
    assert_eq!(installed_zap(room, "x"), Some(Vec::new()));
}

#[test]
fn wrapped_ios_bundle_id_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    // An iOS/iPadOS app on Apple silicon: no `Contents/`, the real bundle in `Wrapper/`.
    let outer = tmp.path().join("apps/Foo.app");
    let inner = outer.join("Wrapper/Foo.app");
    std::fs::create_dir_all(&inner).unwrap();
    let mut dict = plist::Dictionary::new();
    dict.insert("CFBundleIdentifier".into(), "com.vendor.foo".into());
    dict.insert("CFBundleShortVersionString".into(), "2.0".into());
    plist::Value::Dictionary(dict)
        .to_file_xml(inner.join("Info.plist"))
        .unwrap();
    let m = read_bundle(&outer);
    assert_eq!(m.bundle_id.as_deref(), Some("com.vendor.foo"));
    assert_eq!(m.version.as_deref(), Some("2.0"));
    let ids = discky_core::findings::apps::leftovers::installed_bundle_ids(&[(
        &tmp.path().join("apps"),
        1,
    )]);
    assert_eq!(ids.get("com.vendor.foo").map(String::as_str), Some("Foo"));

    // Through the `WrappedBundle` symlink when `Wrapper/` holds no `.app` directly.
    let bar = tmp.path().join("other/Bar.app");
    let real = bar.join("Wrapper/Payload/Bar.app");
    std::fs::create_dir_all(&real).unwrap();
    let mut dict = plist::Dictionary::new();
    dict.insert("CFBundleIdentifier".into(), "com.vendor.bar".into());
    plist::Value::Dictionary(dict)
        .to_file_xml(real.join("Info.plist"))
        .unwrap();
    std::os::unix::fs::symlink("Wrapper/Payload/Bar.app", bar.join("WrappedBundle")).unwrap();
    assert_eq!(
        read_bundle(&bar).bundle_id.as_deref(),
        Some("com.vendor.bar")
    );
}

#[test]
fn spotlight_bundle_id_lines_are_parsed() {
    use discky_core::findings::apps::last_used::parse_bundle_ids;
    let text = "/Applications/Safari.app   kMDItemCFBundleIdentifier = com.apple.Safari\n\
                /Applications/Foo.app/Wrapper/Foo.app   kMDItemCFBundleIdentifier = \"com.vendor.foo\"\n\
                /Volumes/X/Old Thing.app   kMDItemCFBundleIdentifier = (null)\n\
                garbage\n";
    let ids = parse_bundle_ids(text);
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_eq!(ids["com.apple.Safari"], "Safari");
    assert_eq!(ids["com.vendor.foo"], "Foo");
}

#[test]
fn cask_binaries_and_script_sudo_are_parsed() {
    let json = r#"{"casks":[{"token":"x","artifacts":[
        {"binary":["$APPDIR/X.app/Contents/MacOS/x-cli",{"target":"x"}]},
        {"binary":["$APPDIR/X.app/Contents/Resources/y"]},
        {"uninstall":[{"script":{"executable":"/usr/bin/true","sudo":true}}]}
    ]}]}"#;
    let casks = parse_casks(json).unwrap();
    assert_eq!(casks[0].binaries, ["x", "y"]);
    assert!(casks[0].uninstall[0].script.as_ref().unwrap().sudo);
}

#[test]
fn empty_spotlight_answer_counts_as_unverified() {
    use discky_core::findings::apps::last_used::spotlight_bundle_ids;
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let fake = |name: &str, body: &str| {
        let p = tmp.path().join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    };
    // Spotlight indexing off: mdfind succeeds and prints nothing.
    let silent = fake("mdfind-silent", "exit 0");
    assert_eq!(spotlight_bundle_ids(Some(&silent)), None);
    let one = fake(
        "mdfind-one",
        "echo '/Applications/A.app   kMDItemCFBundleIdentifier = com.a.app'",
    );
    let ids = spotlight_bundle_ids(Some(&one)).unwrap();
    assert_eq!(ids["com.a.app"], "A");
    assert_eq!(spotlight_bundle_ids(None), None);
}
