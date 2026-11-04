//! App, leftover, receipt and mise removal plans (pure: synthetic findings, fake tools).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use discky_core::{
    config::{Config, RemovalMode},
    findings::{
        AppSource, Component, ComponentKind, ComponentRemoval, Finding, FindingId, Removal,
    },
    plan::{
        ALREADY_GONE, CaskInfo, NOTHING_TO_DO, PARTS_CHANGED, Plan, PlanItem, PlanTools, Step,
        StepFlags, StepKind, ZapInfo, parts_signature, plan_items_with_tools,
    },
    rules::{Category, SafetyLabel},
};

/// `dir/name`, created as a directory.
fn dir(base: &Path, name: &str) -> PathBuf {
    let p = base.join(name);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// `dir/name`, created as a file.
fn file(base: &Path, name: &str) -> PathBuf {
    let p = base.join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"x").unwrap();
    p
}

fn comp(
    kind: ComponentKind,
    path: Option<PathBuf>,
    freed: u64,
    removal: ComponentRemoval,
) -> Component {
    Component {
        title: format!("{kind:?}"),
        kind,
        path,
        allocated: freed,
        freed_if_deleted: freed,
        modified: None,
        default_on: true,
        removal,
        note: None,
        covered_by_cask: false,
    }
}

fn trash_comp(kind: ComponentKind, path: PathBuf, freed: u64) -> Component {
    comp(kind, Some(path), freed, ComponentRemoval::Trash)
}

fn covered(mut c: Component) -> Component {
    c.covered_by_cask = true;
    c
}

fn off(mut c: Component) -> Component {
    c.default_on = false;
    c
}

fn app(title: &str, source: AppSource, bundle: &Path, components: Vec<Component>) -> Finding {
    let freed = components
        .iter()
        .filter(|c| c.default_on)
        .map(|c| c.freed_if_deleted)
        .sum();
    Finding {
        id: FindingId(format!("app:{title}")),
        category: Category::Apps,
        title: title.into(),
        subtitle: None,
        path: Some(bundle.to_path_buf()),
        node: None,
        allocated: freed,
        logical: freed,
        freed_if_deleted: freed,
        modified: None,
        label: SafetyLabel::AppData,
        rule_id: "apps".into(),
        explain: String::new(),
        removal: Removal::App {
            source,
            bundle: bundle.to_path_buf(),
            bundle_id: Some(format!("com.example.{}", title.to_lowercase())),
        },
        flags: vec![],
        components,
    }
}

fn plan(f: &Finding, components: Option<Vec<usize>>, tools: &PlanTools) -> Plan {
    plan_with(f, components, tools, &Config::default())
}

fn plan_with(f: &Finding, components: Option<Vec<usize>>, tools: &PlanTools, cfg: &Config) -> Plan {
    let items = [PlanItem {
        id: f.id.0.clone(),
        components,
        parts: None,
    }];
    plan_items_with_tools(&items, &[f], cfg, tools)
}

/// Plan `f` with the given component selection and parts signature.
fn plan_parts(f: &Finding, components: Option<Vec<usize>>, parts: Option<u64>) -> Plan {
    let items = [PlanItem {
        id: f.id.0.clone(),
        components,
        parts,
    }];
    plan_items_with_tools(&items, &[f], &Config::default(), &PlanTools::default())
}

fn argv(s: &Step) -> Vec<&str> {
    match &s.kind {
        StepKind::Command { argv, .. } => argv.iter().map(String::as_str).collect(),
        other => panic!("not a command: {other:?}"),
    }
}

fn trashed(s: &Step) -> &[PathBuf] {
    match &s.kind {
        StepKind::Trash { paths } | StepKind::Remove { paths } => paths,
        other => panic!("not a trash step: {other:?}"),
    }
}

fn brew_tools() -> PlanTools {
    PlanTools {
        brew: Some("/fake/bin/brew".into()),
        ..PlanTools::default()
    }
}

/// brew plus a cask whose zap stanza names `paths` (and other directives when `other`).
fn zap_tools(paths: Vec<PathBuf>, other: bool) -> PlanTools {
    PlanTools {
        cask_info: Box::new(move |token| {
            assert_eq!(token, "raycast");
            Some(CaskInfo {
                zap: ZapInfo {
                    paths: paths.clone(),
                    non_path_directives: other,
                },
                ..CaskInfo::default()
            })
        }),
        ..brew_tools()
    }
}

/// Bundle (covered), caches (covered), Application Support, a user settings domain.
fn cask_app(t: &Path) -> Finding {
    let bundle = dir(t, "Raycast.app");
    app(
        "Raycast",
        AppSource::Cask {
            token: "raycast".into(),
            full_token: "raycast".into(),
        },
        &bundle,
        vec![
            covered(trash_comp(ComponentKind::AppBundle, bundle.clone(), 100)),
            covered(trash_comp(ComponentKind::Caches, dir(t, "caches"), 30)),
            trash_comp(ComponentKind::ApplicationSupport, dir(t, "support"), 7),
            comp(
                ComponentKind::Preferences,
                Some(file(t, "com.raycast.macos.plist")),
                1,
                ComponentRemoval::Defaults {
                    domain: "com.raycast.macos".into(),
                },
            ),
        ],
    )
}

#[test]
fn cask_plan_runs_brew_zap_and_skips_zap_components() {
    let t = tempfile::tempdir().unwrap();
    let f = cask_app(t.path());
    let p = plan(
        &f,
        None,
        &zap_tools(vec![t.path().join("caches/sub")], false),
    );
    assert_eq!(p.steps.len(), 3, "{:#?}", p.steps);
    let brew = &p.steps[0];
    assert_eq!(
        argv(brew),
        ["/fake/bin/brew", "uninstall", "--cask", "--zap", "raycast"]
    );
    let StepKind::Command { env, cwd, .. } = &brew.kind else {
        unreachable!()
    };
    assert_eq!(*cwd, None);
    assert!(env.contains(&("HOMEBREW_NO_AUTO_UPDATE".into(), "1".into())));
    assert!(env.contains(&("HOMEBREW_NO_ANALYTICS".into(), "1".into())));
    assert_eq!(brew.description, "Remove Raycast with Homebrew (zap)");
    assert_eq!(brew.freed, Some(130));
    assert_eq!(brew.component, Some(0));
    assert!(!brew.flags.contains(StepFlags::INTERACTIVE));
    // Only the uncovered leftovers get their own steps: support, then settings.
    assert_eq!(trashed(&p.steps[1]), [t.path().join("support")]);
    assert_eq!(p.steps[1].component, Some(2));
    assert_eq!(
        p.steps[1].description,
        "Move ApplicationSupport to the Trash"
    );
    assert_eq!(
        argv(&p.steps[2]),
        ["/usr/bin/defaults", "delete", "com.raycast.macos"]
    );
    assert_eq!(p.total_freed, 138);
    let j = p.to_json();
    assert_eq!(j["steps"][0]["env"]["HOMEBREW_NO_AUTO_UPDATE"], "1");

    // A deselected covered leftover would still be zapped: brew runs without --zap and
    // the selected leftovers are trashed by Discky.
    let p = plan(
        &f,
        Some(vec![0, 2]),
        &zap_tools(vec![t.path().join("caches")], false),
    );
    assert_eq!(
        argv(&p.steps[0]),
        ["/fake/bin/brew", "uninstall", "--cask", "raycast"]
    );
    assert_eq!(p.steps[0].description, "Remove Raycast with Homebrew");
    assert_eq!(p.steps[0].freed, Some(100));
    assert_eq!(p.steps.len(), 2);

    // No brew: the step is flagged, never replaced by a trash fallback.
    let p = plan(&f, None, &PlanTools::default());
    assert!(p.steps[0].flags.contains(StepFlags::TOOL_MISSING));
    assert_eq!(argv(&p.steps[0])[0], "brew");
    assert!(p.steps.iter().all(|s| !matches!(&s.kind, StepKind::Trash { paths } if paths.contains(&t.path().join("Raycast.app")))));
}

#[test]
fn unlisted_zap_path_disables_zap() {
    let t = tempfile::tempdir().unwrap();
    let f = cask_app(t.path());
    let unlisted = dir(t.path(), "someone-elses");
    let p = plan(
        &f,
        None,
        &zap_tools(vec![t.path().join("caches"), unlisted], false),
    );
    assert_eq!(
        argv(&p.steps[0]),
        ["/fake/bin/brew", "uninstall", "--cask", "raycast"]
    );
    assert_eq!(
        p.steps[0].warnings,
        ["Homebrew zap skipped: it would also remove 1 paths not listed here"]
    );
    // The covered caches are trashed by Discky instead.
    assert!(p.steps.iter().any(
        |s| matches!(&s.kind, StepKind::Trash { paths } if paths == &[t.path().join("caches")])
    ));
    assert_eq!(p.total_freed, 138);
    // An unreadable zap stanza never zaps either.
    let p = plan(&f, None, &brew_tools());
    assert_eq!(argv(&p.steps[0]).len(), 4);
}

#[test]
fn non_path_zap_directive_disables_zap() {
    let t = tempfile::tempdir().unwrap();
    let f = cask_app(t.path());
    let p = plan(&f, None, &zap_tools(vec![t.path().join("caches")], true));
    assert_eq!(
        argv(&p.steps[0]),
        ["/fake/bin/brew", "uninstall", "--cask", "raycast"]
    );
    assert!(
        p.steps[0].warnings[0].starts_with("Homebrew zap skipped"),
        "{:?}",
        p.steps[0].warnings
    );
}

#[test]
fn covered_loaded_agent_is_booted_out_before_brew() {
    let t = tempfile::tempdir().unwrap();
    let mut f = cask_app(t.path());
    let plist = file(t.path(), "com.raycast.agent.plist");
    f.components.push(covered(comp(
        ComponentKind::LaunchAgent,
        Some(plist.clone()),
        2,
        ComponentRemoval::Bootout {
            label: "com.raycast.agent".into(),
            system: false,
        },
    )));
    let tools = PlanTools {
        launchctl_probe: Box::new(|label, _| label == "com.raycast.agent"),
        ..zap_tools(vec![t.path().join("caches"), plist.clone()], false)
    };
    let p = plan(&f, None, &tools);
    assert_eq!(argv(&p.steps[0])[..2], ["/bin/launchctl", "bootout"]);
    assert_eq!(
        argv(&p.steps[1])[..4],
        ["/fake/bin/brew", "uninstall", "--cask", "--zap"]
    );
    // brew zaps the plist.
    assert!(
        p.steps
            .iter()
            .all(|s| !matches!(&s.kind, StepKind::Trash { paths } if paths.contains(&plist)))
    );
    // Without zap the plist is trashed by Discky, still after the bootout.
    let tools = PlanTools {
        launchctl_probe: Box::new(|label, _| label == "com.raycast.agent"),
        ..brew_tools()
    };
    let p = plan(&f, None, &tools);
    assert_eq!(argv(&p.steps[0])[..2], ["/bin/launchctl", "bootout"]);
    assert_eq!(argv(&p.steps[1]).len(), 4);
    assert!(
        p.steps
            .iter()
            .any(|s| matches!(&s.kind, StepKind::Trash { paths } if paths.contains(&plist)))
    );
}

#[test]
fn zap_shared_cask_runs_without_zap_and_trashes_components() {
    let t = tempfile::tempdir().unwrap();
    let mut f = cask_app(t.path());
    f.flags.push("zap-shared".into());
    let p = plan(&f, None, &brew_tools());
    assert_eq!(
        argv(&p.steps[0]),
        ["/fake/bin/brew", "uninstall", "--cask", "raycast"]
    );
    assert_eq!(p.steps[0].freed, Some(100));
    let trashes: Vec<&[PathBuf]> = p
        .steps
        .iter()
        .filter(|s| matches!(s.kind, StepKind::Trash { .. }))
        .map(trashed)
        .collect();
    assert_eq!(
        trashes,
        [[t.path().join("caches")], [t.path().join("support")]]
    );
    assert_eq!(p.total_freed, 138);
}

#[test]
fn running_cask_app_quits_itself_and_its_running_quit_ids() {
    let t = tempfile::tempdir().unwrap();
    let mut f = cask_app(t.path());
    f.flags.push("app-running".into());
    let tools = PlanTools {
        running: HashSet::from(["com.raycast.helper".to_string()]),
        cask_quit: Box::new(|token| {
            assert_eq!(token, "raycast");
            vec![
                "com.example.raycast".into(),
                "com.raycast.helper".into(),
                "com.raycast.not-running".into(),
            ]
        }),
        ..brew_tools()
    };
    let p = plan(&f, None, &tools);
    let quits: Vec<&str> = p
        .steps
        .iter()
        .filter_map(|s| match &s.kind {
            StepKind::Quit { bundle_id } => Some(bundle_id.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(quits, ["com.example.raycast", "com.raycast.helper"]);
    assert!(matches!(p.steps[0].kind, StepKind::Quit { .. }));
    assert!(matches!(p.steps[1].kind, StepKind::Quit { .. }));
    assert!(p.steps[0].flags.contains(StepFlags::INTERACTIVE));
    assert_eq!(p.steps[0].freed, None);
}

#[test]
fn pkg_plan_trashes_files_then_forgets() {
    let t = tempfile::tempdir().unwrap();
    let home = dir(t.path(), "home");
    let bundle = dir(t.path(), "zoom.us.app");
    let home_file = file(&home, "Library/Zoom/plugin.bin");
    let receipt = file(t.path(), "receipts/us.zoom.pkg.plist");
    let files: Vec<PathBuf> = vec![
        home.join("Library"),
        home.join("Library/Zoom"),
        bundle.clone(),
        bundle.join("Contents"),
        file(&bundle, "Contents/Info.plist"),
        home_file.clone(),
        home.join("Library/Zoom/gone.bin"),
        "/usr/local/bin/zoom-cli".into(),
        "/Library/Apple/zoom".into(),
    ];
    let tools = PlanTools {
        home: Some(home.clone()),
        pkg_files: Box::new(move |id| {
            assert_eq!(id, "us.zoom.pkg");
            files.clone()
        }),
        ..PlanTools::default()
    };
    let f = app(
        "Zoom",
        AppSource::Pkg {
            pkg_ids: vec!["us.zoom.pkg".into()],
        },
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 100),
            trash_comp(ComponentKind::Caches, dir(t.path(), "zoom-caches"), 5),
            comp(
                ComponentKind::Receipt,
                Some(receipt.clone()),
                0,
                ComponentRemoval::PkgForget {
                    pkg_id: "us.zoom.pkg".into(),
                },
            ),
            comp(
                ComponentKind::Preferences,
                Some(file(t.path(), "us.zoom.xos.plist")),
                1,
                ComponentRemoval::Defaults {
                    domain: "us.zoom.xos".into(),
                },
            ),
        ],
    );
    let p = plan(&f, None, &tools);
    assert_eq!(p.steps.len(), 4, "{:#?}", p.steps);
    // Bundle and the installed home file in one step; dirs and missing files left out.
    assert_eq!(trashed(&p.steps[0]), [bundle.clone(), home_file]);
    assert_eq!(p.steps[0].component, Some(0));
    assert_eq!(p.steps[0].freed, Some(100));
    assert!(p.steps[0].flags.contains(StepFlags::SOURCE));
    assert!(
        !p.steps[1].flags.contains(StepFlags::SOURCE),
        "a leftover path"
    );
    let w = &p.steps[0].warnings;
    assert!(
        w.contains(&"left in place: /usr/local/bin/zoom-cli".to_string()),
        "{w:?}"
    );
    assert!(
        w.contains(&"left in place: /Library/Apple/zoom".to_string()),
        "{w:?}"
    );
    assert_eq!(trashed(&p.steps[1]), [t.path().join("zoom-caches")]);
    assert_eq!(
        argv(&p.steps[2]),
        ["/usr/bin/defaults", "delete", "us.zoom.xos"]
    );
    let forget = &p.steps[3];
    assert_eq!(
        argv(forget),
        ["/usr/sbin/pkgutil", "--forget", "us.zoom.pkg"]
    );
    assert!(forget.flags.contains(StepFlags::INTERACTIVE));
    assert_eq!(forget.component, Some(2));
    assert_eq!(forget.description, "Forget package receipt us.zoom.pkg");
    let StepKind::Command { cwd, .. } = &forget.kind else {
        unreachable!()
    };
    assert_eq!(*cwd, None);
}

#[test]
fn dragged_plan_is_a_trash_step() {
    let t = tempfile::tempdir().unwrap();
    for source in [AppSource::Dragged, AppSource::AppStore] {
        let bundle = dir(t.path(), "Thing.app");
        let f = app(
            "Thing",
            source,
            &bundle,
            vec![trash_comp(ComponentKind::AppBundle, bundle.clone(), 42)],
        );
        let p = plan(&f, None, &PlanTools::default());
        assert_eq!(p.steps.len(), 1);
        assert_eq!(trashed(&p.steps[0]), std::slice::from_ref(&bundle));
        assert!(matches!(p.steps[0].kind, StepKind::Trash { .. }));
        assert_eq!(p.steps[0].component, Some(0));
        assert_eq!(p.steps[0].freed, Some(42));
        assert!(!p.steps[0].flags.contains(StepFlags::INTERACTIVE));
        assert!(p.steps[0].flags.contains(StepFlags::SOURCE));
        // Internal to the executor: never one of the exported flag names.
        assert!(!p.steps[0].flags.names().contains(&"source"));
        let mut cfg = Config::default();
        cfg.removal.mode = RemovalMode::Permanent;
        let p = plan_with(&f, None, &PlanTools::default(), &cfg);
        assert!(matches!(p.steps[0].kind, StepKind::Remove { .. }));
        assert!(p.steps[0].flags.contains(StepFlags::PERMANENT));
    }
}

#[test]
fn root_owned_bundle_step_is_interactive() {
    // Planned only, never executed.
    let bundle = Path::new("/System/Applications/Calculator.app");
    assert!(bundle.exists());
    let f = app(
        "Calculator",
        AppSource::Dragged,
        bundle,
        vec![trash_comp(ComponentKind::AppBundle, bundle.into(), 1)],
    );
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 1);
    assert!(p.steps[0].flags.contains(StepFlags::INTERACTIVE));
}

#[test]
fn loaded_daemon_gets_bootout_then_trash() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "Zoom.app");
    let daemon = file(t.path(), "us.zoom.ZoomDaemon.plist");
    let agent = file(t.path(), "us.zoom.updater.plist");
    let user_agent = file(t.path(), "us.zoom.ui.plist");
    let f = app(
        "Zoom",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 100),
            comp(
                ComponentKind::LaunchDaemon,
                Some(daemon.clone()),
                4,
                ComponentRemoval::Bootout {
                    label: "us.zoom.ZoomDaemon".into(),
                    system: true,
                },
            ),
            comp(
                ComponentKind::LaunchAgent,
                Some(agent.clone()),
                4,
                ComponentRemoval::Bootout {
                    label: "us.zoom.updater".into(),
                    system: false,
                },
            ),
            comp(
                ComponentKind::LaunchAgent,
                Some(user_agent.clone()),
                4,
                ComponentRemoval::Bootout {
                    label: "us.zoom.ui".into(),
                    system: false,
                },
            ),
        ],
    );
    let tools = PlanTools {
        launchctl_probe: Box::new(|label, system| match label {
            "us.zoom.ZoomDaemon" => system,
            "us.zoom.ui" => !system,
            _ => false,
        }),
        ..PlanTools::default()
    };
    let p = plan(&f, None, &tools);
    assert_eq!(p.steps.len(), 6, "{:#?}", p.steps);
    let uid = unsafe { libc::getuid() };
    assert_eq!(
        argv(&p.steps[0]),
        ["/bin/launchctl", "bootout", "system/us.zoom.ZoomDaemon"]
    );
    assert!(p.steps[0].flags.contains(StepFlags::INTERACTIVE));
    assert_eq!(
        p.steps[0].description,
        "Unload launch daemon us.zoom.ZoomDaemon"
    );
    assert_eq!(p.steps[0].component, Some(1));
    let gui = format!("gui/{uid}/us.zoom.ui");
    assert_eq!(
        argv(&p.steps[1]),
        ["/bin/launchctl", "bootout", gui.as_str()]
    );
    assert!(!p.steps[1].flags.contains(StepFlags::INTERACTIVE));
    assert_eq!(p.steps[1].description, "Unload launch agent us.zoom.ui");
    // Bundle, then every plist (the not-loaded agent is only trashed).
    assert_eq!(trashed(&p.steps[2]), [bundle]);
    assert_eq!(trashed(&p.steps[3]), [daemon]);
    assert_eq!(p.steps[3].component, Some(1));
    assert_eq!(trashed(&p.steps[4]), [agent]);
    assert_eq!(trashed(&p.steps[5]), [user_agent]);
    assert_eq!(p.total_freed, 112);
}

#[test]
fn preferences_use_defaults_delete() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "X.app");
    let plist = file(t.path(), "com.x.y.plist");
    let f = app(
        "X",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            comp(
                ComponentKind::Preferences,
                Some(plist.clone()),
                3,
                ComponentRemoval::Defaults {
                    domain: "com.x.y".into(),
                },
            ),
        ],
    );
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 2);
    let d = &p.steps[1];
    assert_eq!(argv(d), ["/usr/bin/defaults", "delete", "com.x.y"]);
    assert_eq!(d.description, "Delete settings domain com.x.y");
    assert!(!d.flags.contains(StepFlags::INTERACTIVE));
    assert_eq!(d.component, Some(1));
    assert_eq!(d.freed, Some(3));
    assert_eq!(d.fingerprints[0].path, plist);
    // The plist itself is never trashed.
    assert!(
        p.steps
            .iter()
            .all(|s| !matches!(&s.kind, StepKind::Trash { paths } if paths.contains(&plist)))
    );
}

#[test]
fn system_preferences_domain_is_interactive() {
    // A domain given as a path under /Library/Preferences is system scope (planned only).
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "X.app");
    let f = app(
        "X",
        AppSource::Dragged,
        &bundle,
        vec![
            off(trash_comp(ComponentKind::AppBundle, bundle.clone(), 10)),
            comp(
                ComponentKind::Preferences,
                None,
                3,
                ComponentRemoval::Defaults {
                    domain: "/Library/Preferences/com.vendor.helper".into(),
                },
            ),
        ],
    );
    let p = plan(&f, Some(vec![1]), &PlanTools::default());
    assert_eq!(p.steps.len(), 1, "{:#?}", p.steps);
    assert_eq!(
        argv(&p.steps[0]),
        [
            "/usr/bin/defaults",
            "delete",
            "/Library/Preferences/com.vendor.helper"
        ]
    );
    assert!(p.steps[0].flags.contains(StepFlags::INTERACTIVE));
}

#[test]
fn unselected_components_produce_no_steps() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "Y.app");
    let caches = dir(t.path(), "caches");
    let f = app(
        "Y",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            off(trash_comp(ComponentKind::Caches, caches.clone(), 3)),
            off(comp(
                ComponentKind::Preferences,
                Some(file(t.path(), "com.y.plist")),
                1,
                ComponentRemoval::Defaults {
                    domain: "com.y".into(),
                },
            )),
            off(comp(
                ComponentKind::LaunchAgent,
                Some(file(t.path(), "com.y.agent.plist")),
                1,
                ComponentRemoval::Bootout {
                    label: "com.y.agent".into(),
                    system: false,
                },
            )),
        ],
    );
    let loaded = PlanTools {
        launchctl_probe: Box::new(|_, _| true),
        ..PlanTools::default()
    };
    let p = plan(&f, None, &loaded);
    assert_eq!(p.steps.len(), 1);
    assert_eq!(trashed(&p.steps[0]), [bundle]);
    let p = plan(&f, Some(vec![1]), &loaded);
    assert_eq!(p.steps.len(), 1);
    assert_eq!(trashed(&p.steps[0]), [caches]);
    let p = plan(&f, Some(vec![]), &loaded);
    assert!(p.steps.is_empty());
    assert_eq!(p.skipped[0].1, "Nothing selected");
}

fn mise_finding(removal: Removal) -> Finding {
    let t = std::env::temp_dir().join("discky-plan-apps-mise-node");
    std::fs::create_dir_all(&t).unwrap();
    Finding {
        id: FindingId("mise:node@19.9.0".into()),
        category: Category::DevCaches,
        title: "node 19.9.0".into(),
        subtitle: None,
        path: Some(t),
        node: None,
        allocated: 77,
        logical: 77,
        freed_if_deleted: 77,
        modified: None,
        label: SafetyLabel::AppData,
        rule_id: "mise-version".into(),
        explain: String::new(),
        removal,
        flags: vec![],
        components: vec![off(comp(
            ComponentKind::Project,
            Some("/tmp/proj/mise.toml".into()),
            0,
            ComponentRemoval::None,
        ))],
    }
}

#[test]
fn mise_uninstall_step_and_global_skip() {
    let f = mise_finding(Removal::MiseUninstall {
        tool: "node".into(),
        version: "19.9.0".into(),
    });
    let tools = PlanTools {
        mise: Some("/fake/bin/mise".into()),
        ..PlanTools::default()
    };
    let p = plan(&f, None, &tools);
    assert_eq!(p.steps.len(), 1);
    assert_eq!(
        argv(&p.steps[0]),
        ["/fake/bin/mise", "uninstall", "node@19.9.0"]
    );
    assert_eq!(p.steps[0].freed, Some(77));
    assert!(!p.steps[0].flags.contains(StepFlags::TOOL_MISSING));
    // A requesting project is shown only: selecting it is refused.
    let p = plan(&f, Some(vec![0]), &tools);
    assert!(p.steps.is_empty());
    assert_eq!(p.skipped[0].1, "Component 0 is shown only");

    let p = plan(&f, None, &PlanTools::default());
    assert!(p.steps[0].flags.contains(StepFlags::TOOL_MISSING));
    assert_eq!(argv(&p.steps[0])[0], "mise");

    let g = mise_finding(Removal::None);
    let p = plan(&g, None, &tools);
    assert!(p.steps.is_empty());
    assert_eq!(
        p.skipped[0].1,
        "Global version — change it in ~/.config/mise/config.toml first"
    );
}

#[test]
fn own_uninstaller_app_becomes_a_warning() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "Tailscale.app");
    let app_uninstaller = dir(&bundle, "Contents/Resources/Uninstall Tailscale.app");
    let f = app(
        "Tailscale",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            off(comp(
                ComponentKind::OwnUninstaller,
                Some(app_uninstaller.clone()),
                0,
                ComponentRemoval::None,
            )),
        ],
    );
    // Shown only, so it cannot be selected: the warning comes with the bundle step.
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 1);
    assert_eq!(
        p.steps[0].warnings,
        [format!(
            "Run Tailscale's own uninstaller first ({})",
            app_uninstaller.display()
        )]
    );
    // Without the bundle step there is nothing to warn about.
    let p = plan(&f, Some(vec![]), &PlanTools::default());
    assert!(p.steps.is_empty());
}

#[test]
fn own_uninstaller_script_is_interactive_and_selectable() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "Tailscale.app");
    for (name, program) in [
        ("uninstall.sh", "/bin/sh"),
        ("Uninstall.scpt", "/usr/bin/osascript"),
    ] {
        let script = file(&bundle, &format!("Contents/Resources/{name}"));
        let f = app(
            "Tailscale",
            AppSource::Dragged,
            &bundle,
            vec![
                trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
                // Opt-in, as the finding builder makes it.
                off(comp(
                    ComponentKind::OwnUninstaller,
                    Some(script.clone()),
                    0,
                    ComponentRemoval::RunScript,
                )),
            ],
        );
        // Checked: it runs as the user (GUI only, never the admin route), before the
        // bundle step, and gates the finding's later steps.
        let p = plan(&f, Some(vec![0, 1]), &PlanTools::default());
        assert_eq!(p.steps.len(), 2, "{:#?}", p.steps);
        assert_eq!(argv(&p.steps[0]), [program, script.to_str().unwrap()]);
        assert_eq!(p.steps[0].component, Some(1));
        assert_eq!(p.steps[0].fingerprints[0].path, script);
        assert_eq!(p.steps[0].freed, None);
        assert!(p.steps[0].flags.contains(StepFlags::GUI_ONLY));
        assert!(p.steps[0].flags.contains(StepFlags::GATE));
        assert!(!p.steps[0].flags.contains(StepFlags::INTERACTIVE));
        assert!(p.steps[0].warnings.is_empty());
        assert!(matches!(p.steps[1].kind, StepKind::Trash { .. }));
        assert_eq!(
            p.to_json()["steps"][0]["flags"],
            serde_json::json!(["gui_only", "gate"])
        );
        // Default selection (unchecked): no script step.
        for selection in [None, Some(vec![0])] {
            let p = plan(&f, selection, &PlanTools::default());
            assert_eq!(p.steps.len(), 1);
        }
        // Running app: quit, then the script, then the bundle.
        let mut running = f.clone();
        running.flags.push("app-running".into());
        let p = plan(&running, Some(vec![0, 1]), &PlanTools::default());
        assert!(p.steps[0].flags.contains(StepFlags::GATE));
        assert!(matches!(p.steps[0].kind, StepKind::Quit { .. }));
        assert_eq!(argv(&p.steps[1])[0], program);
        assert!(matches!(p.steps[2].kind, StepKind::Trash { .. }));
    }
}

#[test]
fn none_components_are_refused_when_selected() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "Foo.app");
    let support = dir(t.path(), "support");
    let f = app(
        "Foo",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            trash_comp(ComponentKind::ApplicationSupport, support, 5),
            off(comp(ComponentKind::Other, None, 0, ComponentRemoval::None)),
        ],
    );
    let p = plan(&f, Some(vec![0, 2]), &PlanTools::default());
    assert!(p.steps.is_empty(), "{:#?}", p.steps);
    assert_eq!(
        p.skipped,
        [(f.id.clone(), "Component 2 is shown only".to_string())]
    );
    // The default selection never includes it.
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 2);
    assert!(p.skipped.is_empty());
}

#[test]
fn leftover_group_plans_components_only() {
    let t = tempfile::tempdir().unwrap();
    let a = dir(t.path(), "com.gone.app-support");
    let b = dir(t.path(), "com.gone.app-container");
    let prefs = file(t.path(), "com.gone.app.plist");
    let f = Finding {
        id: FindingId("app-leftovers:com.gone".into()),
        category: Category::Apps,
        title: "Gone".into(),
        subtitle: None,
        path: None,
        node: None,
        allocated: 6,
        logical: 6,
        freed_if_deleted: 6,
        modified: None,
        label: SafetyLabel::AppData,
        rule_id: "app-leftovers".into(),
        explain: String::new(),
        removal: Removal::Trash {
            paths: vec![a.clone()],
        },
        flags: vec![],
        components: vec![
            trash_comp(ComponentKind::ApplicationSupport, a.clone(), 5),
            off(trash_comp(ComponentKind::Container, b.clone(), 900)),
            comp(
                ComponentKind::Preferences,
                Some(prefs),
                1,
                ComponentRemoval::Defaults {
                    domain: "com.gone.app".into(),
                },
            ),
        ],
    };
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 2, "{:#?}", p.steps);
    assert_eq!(trashed(&p.steps[0]), [a]);
    assert_eq!(p.steps[0].component, Some(0));
    assert_eq!(
        argv(&p.steps[1]),
        ["/usr/bin/defaults", "delete", "com.gone.app"]
    );
    assert_eq!(p.total_freed, 6);
    let p = plan(&f, Some(vec![1]), &PlanTools::default());
    assert_eq!(p.steps.len(), 1);
    assert_eq!(trashed(&p.steps[0]), [b]);
}

#[test]
fn orphan_receipts_plan_pkg_forget_only() {
    let t = tempfile::tempdir().unwrap();
    let receipt = |id: &str| {
        comp(
            ComponentKind::Receipt,
            Some(file(t.path(), &format!("{id}.plist"))),
            0,
            ComponentRemoval::PkgForget { pkg_id: id.into() },
        )
    };
    let f = Finding {
        id: FindingId("pkg-receipts:orphans".into()),
        category: Category::Apps,
        title: "Package receipts of removed apps".into(),
        subtitle: None,
        path: None,
        node: None,
        allocated: 0,
        logical: 0,
        freed_if_deleted: 0,
        modified: None,
        label: SafetyLabel::NeedsPassword,
        rule_id: "pkg-receipts".into(),
        explain: String::new(),
        removal: Removal::Trash { paths: Vec::new() },
        flags: vec![],
        components: vec![receipt("com.a.pkg"), receipt("com.b.pkg")],
    };
    let p = plan(&f, None, &PlanTools::default());
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    assert_eq!(p.steps.len(), 2);
    assert_eq!(
        argv(&p.steps[0]),
        ["/usr/sbin/pkgutil", "--forget", "com.a.pkg"]
    );
    assert_eq!(
        argv(&p.steps[1]),
        ["/usr/sbin/pkgutil", "--forget", "com.b.pkg"]
    );
    assert!(
        p.steps
            .iter()
            .all(|s| s.flags.contains(StepFlags::INTERACTIVE))
    );
}

#[test]
fn buckets_order_steps_across_findings() {
    let t = tempfile::tempdir().unwrap();
    let mut first = cask_app(t.path());
    first.flags.push("app-running".into());
    let receipts = Finding {
        id: FindingId("pkg-receipts:orphans".into()),
        removal: Removal::Trash { paths: Vec::new() },
        components: vec![comp(
            ComponentKind::Receipt,
            Some(file(t.path(), "r.plist")),
            0,
            ComponentRemoval::PkgForget {
                pkg_id: "com.r.pkg".into(),
            },
        )],
        ..first.clone()
    };
    let items = [
        PlanItem::defaults(&receipts.id),
        PlanItem::defaults(&first.id),
    ];
    let p = plan_items_with_tools(
        &items,
        &[&receipts, &first],
        &Config::default(),
        &zap_tools(vec![t.path().join("caches")], false),
    );
    let kinds: Vec<&str> = p
        .steps
        .iter()
        .map(|s| match &s.kind {
            StepKind::Quit { .. } => "quit",
            StepKind::Command { argv, .. } if argv[0].ends_with("brew") => "brew",
            StepKind::Command { argv, .. } if argv[0].ends_with("defaults") => "defaults",
            StepKind::Command { argv, .. } if argv[0].ends_with("pkgutil") => "forget",
            StepKind::Trash { .. } => "trash",
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(kinds, ["quit", "brew", "trash", "defaults", "forget"]);
    let idx: Vec<usize> = p.steps.iter().map(|s| s.index).collect();
    assert_eq!(idx, [0, 1, 2, 3, 4]);
}

#[test]
fn shared_pkg_receipt_is_kept() {
    let t = tempfile::tempdir().unwrap();
    let home = dir(t.path(), "home");
    let bundle = dir(t.path(), "Word.app");
    let other = dir(t.path(), "Excel.app");
    let shared_file = file(&home, "Library/MS/shared.bin");
    let own_file = file(&home, "Library/MS/word.bin");
    let receipt = |id: &str| {
        comp(
            ComponentKind::Receipt,
            Some(file(t.path(), &format!("{id}.plist"))),
            0,
            ComponentRemoval::PkgForget { pkg_id: id.into() },
        )
    };
    let files = {
        let (bundle, other, shared_file, own_file) = (
            bundle.clone(),
            other.clone(),
            shared_file.clone(),
            own_file.clone(),
        );
        move |id: &str| match id {
            "com.ms.word" => vec![bundle.clone(), own_file.clone()],
            "com.ms.shared" => vec![
                bundle.clone(),
                other.join("Contents"),
                other.clone(),
                shared_file.clone(),
            ],
            _ => Vec::new(),
        }
    };
    let tools = PlanTools {
        home: Some(home.clone()),
        pkg_files: Box::new(files),
        ..PlanTools::default()
    };
    let f = app(
        "Word",
        AppSource::Pkg {
            pkg_ids: vec!["com.ms.word".into(), "com.ms.shared".into()],
        },
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 100),
            receipt("com.ms.word"),
            receipt("com.ms.shared"),
        ],
    );
    let p = plan(&f, None, &tools);
    assert_eq!(p.steps.len(), 2, "{:#?}", p.steps);
    assert_eq!(trashed(&p.steps[0]), [bundle, own_file]);
    assert!(
        p.steps[0]
            .warnings
            .contains(&"Package com.ms.shared also installed Excel.app; receipt kept".to_string()),
        "{:?}",
        p.steps[0].warnings
    );
    assert_eq!(
        argv(&p.steps[1]),
        ["/usr/sbin/pkgutil", "--forget", "com.ms.word"]
    );
}

#[test]
fn global_and_apple_domains_are_never_deleted() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "X.app");
    let mut components = vec![trash_comp(ComponentKind::AppBundle, bundle.clone(), 10)];
    for domain in [
        "-g",
        "NSGlobalDomain",
        ".GlobalPreferences",
        "com.apple.finder",
        "/Library/Preferences/.GlobalPreferences",
        "/Library/Preferences/com.apple.TimeMachine",
        "Apple Global Domain",
        "/Library/Preferences/SystemConfiguration/preferences",
        "com.vendor/../com.apple.finder",
    ] {
        components.push(comp(
            ComponentKind::Preferences,
            None,
            1,
            ComponentRemoval::Defaults {
                domain: domain.into(),
            },
        ));
    }
    let f = app("X", AppSource::Dragged, &bundle, components);
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 1, "{:#?}", p.steps);
    assert!(matches!(p.steps[0].kind, StepKind::Trash { .. }));
    assert_eq!(p.steps[0].warnings.len(), 9, "{:?}", p.steps[0].warnings);
    assert_eq!(
        p.steps[0].warnings[3],
        "Settings domain com.apple.finder is never deleted"
    );

    // The final target is checked too: a plain domain whose plist sits in a subfolder
    // of /Library/Preferences (planned only; the plist exists on every Mac).
    let plist = PathBuf::from("/Library/Preferences/SystemConfiguration/preferences.plist");
    assert!(plist.exists());
    let f = app(
        "X",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            comp(
                ComponentKind::Preferences,
                Some(plist),
                1,
                ComponentRemoval::Defaults {
                    domain: "preferences".into(),
                },
            ),
        ],
    );
    let p = plan(&f, None, &PlanTools::default());
    assert_eq!(p.steps.len(), 1, "{:#?}", p.steps);
    assert_eq!(
        p.steps[0].warnings,
        ["Settings domain preferences is never deleted"]
    );
}

#[test]
fn brew_step_warns_about_uninstall_stanza_and_other_artifacts() {
    let t = tempfile::tempdir().unwrap();
    let f = cask_app(t.path());
    let bundle = t.path().join("Raycast.app");
    let helper = dir(t.path(), "Raycast Helper.app");
    let bin = file(t.path(), "bin/ray");
    let (helper2, bin2, bundle2) = (helper.clone(), bin.clone(), bundle.clone());
    let tools = PlanTools {
        cask_info: Box::new(move |_| {
            Some(CaskInfo {
                zap: ZapInfo {
                    paths: Vec::new(),
                    non_path_directives: false,
                },
                uninstall_directives: vec![
                    "quit com.raycast.macos".into(),
                    "pkgutil com.raycast.pkg".into(),
                ],
                // The bundle itself is not "also" removed.
                other_app_targets: vec![bundle2.clone(), helper2.clone()],
                binaries: vec![bin2.clone()],
                needs_admin: true,
            })
        }),
        ..brew_tools()
    };
    let p = plan(&f, None, &tools);
    let brew = &p.steps[0];
    assert_eq!(argv(brew)[1], "uninstall");
    assert_eq!(
        brew.warnings,
        [
            "Homebrew will also: quit com.raycast.macos; pkgutil com.raycast.pkg".to_string(),
            format!(
                "Homebrew will also remove: {}, {}",
                helper.display(),
                bin.display()
            ),
            "This cask's uninstall needs administrator rights; if it fails, run \
             `brew uninstall --cask raycast` in Terminal"
                .to_string(),
        ]
    );
    // Nothing known beyond the zap stanza: no extra warnings.
    let p = plan(&f, None, &zap_tools(Vec::new(), false));
    assert!(p.steps[0].warnings.is_empty(), "{:?}", p.steps[0].warnings);
}

#[test]
fn invalid_pkg_ids_and_apple_launch_jobs_are_never_touched() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "Foo.app");
    let receipt = |id: &str| {
        comp(
            ComponentKind::Receipt,
            None,
            0,
            ComponentRemoval::PkgForget { pkg_id: id.into() },
        )
    };
    let apple_plist = file(t.path(), "com.apple.foo.plist");
    let f = app(
        "Foo",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 1),
            receipt("com.example.foo-pkg_1"),
            receipt("-rf"),
            receipt("com.example/../x"),
            receipt("com.example foo"),
            receipt(""),
            comp(
                ComponentKind::LaunchAgent,
                Some(apple_plist.clone()),
                1,
                ComponentRemoval::Bootout {
                    label: "com.Apple.foo".into(),
                    system: false,
                },
            ),
        ],
    );
    let tools = PlanTools {
        launchctl_probe: Box::new(|_, _| true),
        ..PlanTools::default()
    };
    let p = plan(&f, None, &tools);
    let commands: Vec<Vec<&str>> = p
        .steps
        .iter()
        .filter(|s| matches!(s.kind, StepKind::Command { .. }))
        .map(argv)
        .collect();
    assert_eq!(
        commands,
        [["/usr/sbin/pkgutil", "--forget", "com.example.foo-pkg_1"]],
        "{:#?}",
        p.steps
    );
    assert!(
        p.steps
            .iter()
            .all(|s| !matches!(&s.kind, StepKind::Trash { paths } if paths.contains(&apple_plist)))
    );
    let warnings: Vec<&String> = p.steps.iter().flat_map(|s| &s.warnings).collect();
    for w in [
        "Package receipt id -rf is not valid; it is never forgotten",
        "Launch job com.Apple.foo is Apple's; it is never unloaded",
    ] {
        assert!(warnings.iter().any(|x| *x == w), "{w}: {warnings:?}");
    }
}

/// A dragged app with an existing bundle and an Application Support folder.
fn parts_app(t: &Path) -> Finding {
    let bundle = dir(t, "P.app");
    let support = dir(t, "p-support");
    app(
        "P",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            trash_comp(ComponentKind::ApplicationSupport, support, 3),
        ],
    )
}

#[test]
fn stale_parts_signature_skips_the_finding() {
    let t = tempfile::tempdir().unwrap();
    let f = parts_app(t.path());
    let p = plan_parts(&f, Some(vec![1]), Some(parts_signature(&f.components) ^ 1));
    assert!(p.steps.is_empty(), "{:#?}", p.steps);
    assert_eq!(p.skipped[0].1, PARTS_CHANGED);
    // A reload that re-orders the parts changes the signature too.
    let mut swapped = f.components.clone();
    swapped.swap(0, 1);
    let p = plan_parts(&f, Some(vec![1]), Some(parts_signature(&swapped)));
    assert_eq!(p.skipped[0].1, PARTS_CHANGED);
}

#[test]
fn matching_parts_signature_plans_normally() {
    let t = tempfile::tempdir().unwrap();
    let f = parts_app(t.path());
    let p = plan_parts(&f, Some(vec![1]), Some(parts_signature(&f.components)));
    assert_eq!(p.steps.len(), 1, "{:#?}", p.skipped);
    assert_eq!(p.steps[0].component, Some(1));
    assert!(p.skipped.is_empty());
}

#[test]
fn all_selected_paths_gone_reports_already_gone() {
    let t = tempfile::tempdir().unwrap();
    let bundle = dir(t.path(), "G.app");
    let caches = dir(t.path(), "g-caches");
    let logs = dir(t.path(), "g-logs");
    let agent = file(t.path(), "com.apple.g-agent.plist");
    let global = file(t.path(), "g-global.plist");
    let f = app(
        "G",
        AppSource::Dragged,
        &bundle,
        vec![
            trash_comp(ComponentKind::AppBundle, bundle.clone(), 10),
            trash_comp(ComponentKind::Caches, caches.clone(), 3),
            trash_comp(ComponentKind::Logs, logs.clone(), 1),
            // An Apple job is never unloaded; its plist is gone.
            comp(
                ComponentKind::LaunchAgent,
                Some(agent.clone()),
                1,
                ComponentRemoval::Bootout {
                    label: "com.apple.g-agent".into(),
                    system: false,
                },
            ),
            // A protected settings domain whose file still exists.
            comp(
                ComponentKind::Preferences,
                Some(global),
                1,
                ComponentRemoval::Defaults {
                    domain: "NSGlobalDomain".into(),
                },
            ),
        ],
    );
    std::fs::remove_dir(&caches).unwrap();
    std::fs::remove_dir(&logs).unwrap();
    std::fs::remove_file(&agent).unwrap();
    let p = plan_parts(&f, Some(vec![1, 2]), None);
    assert!(p.steps.is_empty(), "{:#?}", p.steps);
    assert_eq!(p.skipped[0].1, ALREADY_GONE);
    // Gone, though no step would have been planned for it anyway.
    let p = plan_parts(&f, Some(vec![3]), None);
    assert_eq!(p.skipped[0].1, ALREADY_GONE);
    // Still there, but never acted on.
    let p = plan_parts(&f, Some(vec![4]), None);
    assert_eq!(p.skipped[0].1, NOTHING_TO_DO);
    // Some gone, some only warned about: not "Already gone".
    let p = plan_parts(&f, Some(vec![1, 4]), None);
    assert_eq!(p.skipped[0].1, NOTHING_TO_DO);
    // Nothing selected stays "Nothing selected".
    let p = plan_parts(&f, Some(vec![]), None);
    assert_eq!(p.skipped[0].1, "Nothing selected");
}
