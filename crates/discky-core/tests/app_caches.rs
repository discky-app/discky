use std::collections::HashSet;

use discky_core::findings::app_caches::{find, owner_of};
use discky_core::fs::walk::{ScanOptions, walk};
use discky_core::rules::SafetyLabel;

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

fn blob(lib: &std::path::Path, p: &str, kb: usize) {
    let dir = lib.join(p);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("blob"), vec![1u8; kb * 1024]).unwrap();
}

#[test]
fn owner_parsing() {
    assert_eq!(owner_of("Caches", "com.openai.codex").app_name, "Codex");
    assert_eq!(
        owner_of("Caches", "com.openai.codex").bundle_id.as_deref(),
        Some("com.openai.codex")
    );
    assert_eq!(
        owner_of("Caches", "com.microsoft.VSCode.ShipIt").app_name,
        "ShipIt"
    );
    let o = owner_of("Group Containers", "HUAQ24HBR6.dev.orbstack");
    assert_eq!(o.bundle_id.as_deref(), Some("dev.orbstack"));
    assert_eq!(o.app_name, "Orbstack");
    assert_eq!(
        owner_of("Group Containers", "group.net.whatsapp.WhatsApp.shared").app_name,
        "WhatsApp"
    );
    assert_eq!(
        owner_of("Application Support", "MacWhisper").app_name,
        "MacWhisper"
    );
    assert_eq!(
        owner_of("Application Support", "MacWhisper").bundle_id,
        None
    );
    assert_eq!(
        owner_of("Saved Application State", "com.apple.Preview.savedState")
            .bundle_id
            .as_deref(),
        Some("com.apple.Preview")
    );
}

#[test]
fn library_children_become_app_cache_findings() {
    let d = tempfile::tempdir().unwrap();
    let lib = d.path().join("Library");
    for (p, kb) in [
        ("Caches/com.example.big", 2048),
        ("Caches/com.example.tiny", 4),
        ("Application Support/Example", 1536),
    ] {
        blob(&lib, p, kb);
    }
    let idx = scan(d.path());
    let mut claimed = HashSet::new();
    let f = find(&idx, d.path(), &mut claimed);
    assert_eq!(f.len(), 2, "tiny cache below 1 MiB is skipped");
    let big = f.iter().find(|f| f.title == "Big").unwrap();
    assert!(matches!(big.label, SafetyLabel::Regenerates));
    assert_eq!(big.rule_id, "app-cache:caches");
    assert_eq!(big.subtitle.as_deref(), Some("Caches · com.example.big"));
    let ex = f.iter().find(|f| f.title == "Example").unwrap();
    assert!(matches!(ex.label, SafetyLabel::AppData));
    assert_eq!(ex.rule_id, "app-cache:application-support");
    assert_eq!(claimed.len(), 2);
}

#[test]
fn claimed_children_are_excluded_from_parent_sizes() {
    let d = tempfile::tempdir().unwrap();
    let lib = d.path().join("Library");
    blob(&lib, "Application Support/Claude", 2048);
    blob(&lib, "Application Support/Claude/vm_bundles", 3072);
    let idx = scan(d.path());
    let vm = idx
        .find(&lib.join("Application Support/Claude/vm_bundles"))
        .unwrap();
    let whole = idx.find(&lib.join("Application Support/Claude")).unwrap();
    let mut claimed = HashSet::from([vm]);
    let f = find(&idx, d.path(), &mut claimed);
    assert_eq!(f.len(), 1);
    assert_eq!(
        f[0].allocated,
        idx.node(whole).agg_allocated - idx.node(vm).agg_allocated
    );
    assert!(claimed.contains(&whole));
}
