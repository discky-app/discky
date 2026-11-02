use discky_core::rules::{Category, Matcher, RuleSet, SafetyLabel};
use std::path::Path;

#[test]
fn builtin_parses_and_has_required_ids() {
    let rs = RuleSet::builtin();
    for id in [
        "cargo-registry",
        "hf-hub",
        "cargo-target",
        "orbstack-disk",
        "keychains",
        "coresimulator",
    ] {
        assert!(rs.get(id).is_some(), "missing rule {id}");
    }
}

#[test]
fn path_rule_matches_expanded_home() {
    let rs = RuleSet::builtin();
    let home = std::env::var("HOME").unwrap();
    let r = rs
        .match_path(Path::new(&format!("{home}/.cargo/registry")))
        .unwrap();
    assert_eq!(r.id, "cargo-registry");
    assert!(matches!(r.category, Category::DevCaches));
    assert!(matches!(r.label, SafetyLabel::Regenerates));
    assert_eq!(r.command.as_ref().unwrap().argv[0], "cargo");
}

#[test]
fn glob_rule_matches_photoslibrary() {
    let rs = RuleSet::builtin();
    let home = std::env::var("HOME").unwrap();
    let r = rs
        .match_path(Path::new(&format!(
            "{home}/Pictures/Photos Library.photoslibrary"
        )))
        .unwrap();
    assert!(matches!(r.label, SafetyLabel::DoNotTouch));
}

#[test]
fn build_rules_are_exposed_separately() {
    let rs = RuleSet::builtin();
    let t = rs.build_rules().find(|r| r.id == "cargo-target").unwrap();
    assert!(
        matches!(&t.matcher, Matcher::BuildDir { name, marker } if name == "target" && marker == "Cargo.toml")
    );
}

#[test]
fn bad_toml_is_an_error_with_rule_id() {
    let e = RuleSet::from_toml("[[rule]]\nid = \"x\"\ncategory = \"nope\"").unwrap_err();
    assert!(e.to_string().contains("x") || e.to_string().contains("category"));
}

#[test]
fn display_names_and_non_matches() {
    assert_eq!(Category::LargeOld.to_string(), "Large & old");
    assert_eq!(Category::AppCaches.to_string(), "App caches");
    let rs = RuleSet::builtin();
    assert!(rs.match_path(Path::new("/nonexistent/place")).is_none());
    // build dirs never match by path
    assert!(rs.match_path(Path::new("/proj/target")).is_none());
}

#[test]
fn toolchains_and_gems_are_app_data_not_regenerates() {
    let rs = RuleSet::builtin();
    for id in ["rustup-toolchains", "gem-cache"] {
        assert_eq!(rs.get(id).unwrap().label, SafetyLabel::AppData, "{id}");
    }
}
