use std::sync::{Mutex, MutexGuard};

use discky_core::{Config, DisckyPaths, RemovalMode};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Points `DISCKY_HOME` at a fresh temp dir; holds a lock so tests that
/// mutate the process environment do not race each other.
fn isolated_home() -> (MutexGuard<'static, ()>, tempfile::TempDir, DisckyPaths) {
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("DISCKY_HOME", dir.path()) };
    let paths = DisckyPaths::resolve();
    (guard, dir, paths)
}

#[test]
fn defaults_match_spec() {
    let c = Config::default();
    assert_eq!(c.thresholds.large_file_bytes, 524_288_000);
    assert_eq!(c.thresholds.old_days, 365);
    assert!(!c.mcp.allow_agent_delete);
    assert!(matches!(c.removal.mode, RemovalMode::Trash));
    assert_eq!(c.scan.roots.len(), 5);
}

#[test]
fn load_missing_file_gives_default_and_save_roundtrips() {
    let (_guard, dir, paths) = isolated_home();
    assert_eq!(paths.config, dir.path().join("config.toml"));
    assert_eq!(paths.snapshot, dir.path().join("snapshot.bin"));
    assert_eq!(paths.log, dir.path().join("removals.log"));
    let mut c = Config::load(&paths).unwrap();
    c.mcp.allow_agent_delete = true;
    c.save(&paths).unwrap();
    assert!(Config::load(&paths).unwrap().mcp.allow_agent_delete);
}

#[test]
fn partial_toml_defaults_other_sections_and_expands_tilde() {
    let (_guard, _dir, paths) = isolated_home();
    std::fs::write(&paths.config, "[scan]\nroots = [\"/x\", \"~/Projects\"]\n").unwrap();
    let c = Config::load(&paths).unwrap();
    let home = std::env::var("HOME").unwrap();
    assert_eq!(c.scan.roots[0], std::path::PathBuf::from("/x"));
    assert_eq!(
        c.scan.roots[1],
        std::path::PathBuf::from(home).join("Projects")
    );
    assert_eq!(c.thresholds.old_days, 365);
}

#[test]
fn removal_mode_serializes_lowercase() {
    let (_guard, _dir, paths) = isolated_home();
    std::fs::write(&paths.config, "[removal]\nmode = \"permanent\"\n").unwrap();
    let c = Config::load(&paths).unwrap();
    assert!(matches!(c.removal.mode, RemovalMode::Permanent));
    c.save(&paths).unwrap();
    assert!(
        std::fs::read_to_string(&paths.config)
            .unwrap()
            .contains("mode = \"permanent\"")
    );
}

#[test]
fn load_missing_file_expands_tilde_in_default_roots() {
    let (_guard, _dir, paths) = isolated_home();
    let c = Config::load(&paths).unwrap();
    let home = std::env::var("HOME").unwrap();
    assert_eq!(c.scan.roots[0].to_str(), Some(home.as_str()));
}

#[test]
fn save_is_atomic_no_tmp_left_behind() {
    let (_guard, dir, paths) = isolated_home();
    let mut c = Config::default();
    c.removal.mode = RemovalMode::Permanent;
    // Absolute roots: `load` expands the defaults' `~`.
    c.scan.roots = vec![dir.path().join("root")];
    c.save(&paths).unwrap();
    assert!(paths.config.exists());
    let tmp: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(tmp.is_empty(), "left behind: {tmp:?}");
    assert_eq!(Config::load(&paths).unwrap(), c);
}

#[test]
fn save_keeps_a_symlinked_config_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("dotfiles").join("discky.toml");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::write(&real, "[mcp]\nallow_agent_delete = false\n").unwrap();
    let paths = DisckyPaths {
        config: dir.path().join("config.toml"),
        snapshot: dir.path().join("snapshot.bin"),
        log: dir.path().join("removals.log"),
    };
    std::os::unix::fs::symlink(&real, &paths.config).unwrap();
    let mut c = Config::load(&paths).unwrap();
    c.mcp.allow_agent_delete = true;
    c.save(&paths).unwrap();
    let meta = std::fs::symlink_metadata(&paths.config).unwrap();
    assert!(meta.file_type().is_symlink(), "config.toml was replaced");
    assert!(Config::load(&paths).unwrap().mcp.allow_agent_delete);
    let target = std::fs::read_to_string(&real).unwrap();
    assert!(target.contains("allow_agent_delete = true"), "{target}");
}
