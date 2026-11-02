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
