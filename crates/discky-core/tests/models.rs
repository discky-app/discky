use std::collections::HashSet;
use std::path::Path;

use discky_core::findings::models::{find, hf_repos, ollama_list, ollama_list_from_manifests};
use discky_core::findings::{Categorizer, Removal};
use discky_core::fs::walk::{ScanOptions, walk};
use discky_core::index::Index;
use discky_core::rules::{RuleSet, SafetyLabel};

const DEAD: &str = "http://127.0.0.1:9";

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

fn manifest(models: &Path, rel: &str, json: &str) {
    let m = models.join("manifests").join(rel);
    std::fs::create_dir_all(m.parent().unwrap()).unwrap();
    std::fs::write(m, json).unwrap();
}

#[test]
fn manifests_fallback_lists_models_with_sizes() {
    let d = tempfile::tempdir().unwrap();
    manifest(
        d.path(),
        "registry.ollama.ai/library/qwen3/4b",
        r#"{"config":{"size":488},"layers":[{"size":1000},{"size":2000}]}"#,
    );
    let v = ollama_list_from_manifests(d.path());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "qwen3:4b");
    assert_eq!(v[0].size, 3488);
}

#[test]
fn hf_repo_names_are_decoded() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("models--Systran--faster-whisper-base")).unwrap();
    let v = hf_repos(d.path());
    assert_eq!(v[0].0, "Systran/faster-whisper-base");
}

#[test]
fn ollama_down_is_an_error_not_a_hang() {
    let t = std::time::Instant::now();
    assert!(ollama_list(DEAD).is_err());
    assert!(t.elapsed().as_secs() < 3);
}

#[test]
#[ignore]
fn ollama_live_matches_cli() {
    let v = ollama_list("http://127.0.0.1:11434").unwrap();
    assert!(v.iter().any(|m| m.name.starts_with("qwen3")));
}

#[test]
fn ollama_findings_from_manifests_account_for_shared_blobs() {
    let d = tempfile::tempdir().unwrap();
    let models = d.path().join(".ollama/models");
    manifest(
        &models,
        "registry.ollama.ai/library/a/latest",
        r#"{"config":{"size":10,"digest":"sha256:c1"},"layers":[{"size":1000,"digest":"sha256:shared"},{"size":200,"digest":"sha256:a"}]}"#,
    );
    manifest(
        &models,
        "registry.ollama.ai/library/b/latest",
        r#"{"config":{"size":10,"digest":"sha256:c2"},"layers":[{"size":1000,"digest":"sha256:shared"}]}"#,
    );
    let idx = scan(d.path());
    let mut claimed = HashSet::new();
    let fs = find(&idx, &RuleSet::builtin(), d.path(), DEAD, &mut claimed);
    let a = fs.iter().find(|f| f.title == "a:latest").unwrap();
    assert_eq!(a.allocated, 1210);
    assert_eq!(a.freed_if_deleted, 210);
    assert!(a.flags.contains(&"shared-blobs".to_string()));
    assert_eq!(
        a.removal,
        Removal::OllamaDelete {
            model: "a:latest".into()
        }
    );
    assert!(a.path.is_none() && a.node.is_none());
    assert_eq!(a.rule_id, "ollama-models");
    let b = fs.iter().find(|f| f.title == "b:latest").unwrap();
    assert_eq!(b.freed_if_deleted, 10);
    assert!(claimed.contains(&idx.find(&models).unwrap()));
}

#[test]
fn ollama_dir_without_models_still_reports_its_bytes() {
    let d = tempfile::tempdir().unwrap();
    let models = d.path().join(".ollama/models");
    std::fs::create_dir_all(models.join("blobs")).unwrap();
    std::fs::write(models.join("blobs/x"), vec![1u8; 8192]).unwrap();
    let idx = scan(d.path());
    let fs = find(
        &idx,
        &RuleSet::builtin(),
        d.path(),
        DEAD,
        &mut HashSet::new(),
    );
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].rule_id, "ollama-models");
    assert!(fs[0].allocated >= 8192);
}

#[test]
fn hf_omlx_lmstudio_one_finding_per_model() {
    let d = tempfile::tempdir().unwrap();
    let h = d.path();
    let put = |p: &str| {
        let dir = h.join(p);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("w.bin"), vec![1u8; 4096]).unwrap();
    };
    put(".cache/huggingface/hub/models--Systran--faster-whisper-base");
    put(".omlx/models/qwen-mlx");
    put(".lmstudio/models/lmstudio-community/gemma-3");
    let idx = scan(h);
    let mut claimed = HashSet::new();
    let fs = find(&idx, &RuleSet::builtin(), h, DEAD, &mut claimed);
    assert_eq!(fs.len(), 3);

    let hf = fs.iter().find(|f| f.rule_id == "hf-hub").unwrap();
    assert_eq!(hf.title, "Systran/faster-whisper-base");
    assert_eq!(hf.label, SafetyLabel::AppData);
    // Always the official tool, installed or not: the planner flags a missing `hf`.
    match &hf.removal {
        Removal::Command {
            tool,
            argv,
            install_hint,
            ..
        } => {
            assert_eq!(tool, "hf");
            assert!(!argv.iter().any(|a| a.contains('{')));
            assert_eq!(argv[3], "Systran/faster-whisper-base");
            assert!(install_hint.is_some());
        }
        other => panic!("unexpected removal {other:?}"),
    }
    assert!(hf.allocated >= 4096 && hf.node.is_some());

    let om = fs.iter().find(|f| f.rule_id == "omlx-models").unwrap();
    assert_eq!(om.title, "qwen-mlx");
    assert!(matches!(om.removal, Removal::Trash { .. }));
    let lm = fs.iter().find(|f| f.rule_id == "lmstudio-models").unwrap();
    assert_eq!(lm.title, "lmstudio-community/gemma-3");
    assert!(matches!(lm.removal, Removal::Trash { .. }));
}

#[test]
fn per_child_rule_never_copies_unsubstituted_placeholders() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("store/item")).unwrap();
    std::fs::write(d.path().join("store/item/f"), vec![1u8; 4096]).unwrap();
    let toml = format!(
        r#"[[rule]]
id = "t"
category = "models"
label = "regenerates"
title = "T"
explain = "x"
per_child = true
[rule.matcher]
kind = "path"
path = "{}"
[rule.command]
tool = "tool"
argv = ["tool", "rm", "{{repo}}"]
"#,
        d.path().join("store").display()
    );
    let rules = RuleSet::from_toml(&toml).unwrap();
    let idx = scan(d.path());
    let th = discky_core::config::Thresholds::default();
    let fs = Categorizer {
        index: &idx,
        rules: &rules,
        thresholds: &th,
    }
    .run_with_home(None);
    let f = fs.iter().find(|f| f.rule_id == "t").unwrap();
    assert_eq!(f.removal, Removal::None);
    assert_eq!(f.explain, "x (removal command template unresolved)");
}

fn put_file(p: &Path, kb: usize) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, vec![1u8; kb * 1024]).unwrap();
}

#[test]
fn hf_datasets_spaces_and_orgless_repos_are_reported() {
    let d = tempfile::tempdir().unwrap();
    let hub = d.path().join(".cache/huggingface/hub");
    put_file(&hub.join("datasets--org--ds/f"), 4);
    put_file(&hub.join("spaces--org--sp/f"), 4);
    put_file(&hub.join("models--gpt2/f"), 4);
    let idx = scan(d.path());
    let fs = find(
        &idx,
        &RuleSet::builtin(),
        d.path(),
        DEAD,
        &mut HashSet::new(),
    );
    let titles: Vec<_> = fs.iter().map(|f| f.title.as_str()).collect();
    for t in ["dataset org/ds", "space org/sp", "gpt2"] {
        assert!(titles.contains(&t), "{titles:?}");
    }
    assert!(fs.iter().all(|f| f.rule_id == "hf-hub"));
    assert_eq!(fs.len(), 3);
}

#[test]
fn residual_is_emitted_only_when_a_store_has_unreported_bytes() {
    let d = tempfile::tempdir().unwrap();
    put_file(&d.path().join(".omlx/models/m1/w"), 4);
    put_file(&d.path().join(".lmstudio/models/pub/m/w"), 4);
    put_file(&d.path().join(".lmstudio/models/loose.bin"), 2048);
    let idx = scan(d.path());
    let mut claimed = HashSet::new();
    let fs = find(&idx, &RuleSet::builtin(), d.path(), DEAD, &mut claimed);
    let res: Vec<_> = fs
        .iter()
        .filter(|f| f.rule_id.ends_with(":residual"))
        .collect();
    assert_eq!(res.len(), 1, "{res:?}");
    let r = res[0];
    assert_eq!(r.rule_id, "lmstudio-models:residual");
    assert_eq!(r.title, "Other data in LM Studio");
    assert!(r.allocated >= 2048 * 1024 && r.allocated < 2200 * 1024);
    assert_eq!(r.removal, Removal::None);
    assert_eq!(r.node, idx.find(&d.path().join(".lmstudio/models")));
    assert!(claimed.contains(&idx.find(&d.path().join(".omlx/models")).unwrap()));
}

#[test]
fn unprocessed_hf_root_is_not_claimed() {
    let d = tempfile::tempdir().unwrap();
    put_file(&d.path().join("other/f"), 4);
    let idx = scan(d.path());
    let mut claimed = HashSet::new();
    let fs = find(&idx, &RuleSet::builtin(), d.path(), DEAD, &mut claimed);
    assert!(fs.is_empty() && claimed.is_empty());
    let hub = d.path().join(".cache/huggingface/hub");
    put_file(&hub.join("models--a--b/f"), 4);
    let idx = scan(d.path());
    find(&idx, &RuleSet::builtin(), d.path(), DEAD, &mut claimed);
    assert!(claimed.contains(&idx.find(&hub).unwrap()));
}

#[test]
fn hf_finding_without_hf_installed_is_planned_as_tool_missing_not_trash() {
    let d = tempfile::tempdir().unwrap();
    put_file(&d.path().join(".cache/huggingface/hub/models--o--n/f"), 4);
    let idx = scan(d.path());
    let fs = find(
        &idx,
        &RuleSet::builtin(),
        d.path(),
        DEAD,
        &mut HashSet::new(),
    );
    let plan = discky_core::plan::plan_removal(&[&fs[0]], &discky_core::config::Config::default());
    let s = &plan.steps[0];
    assert!(
        matches!(s.kind, discky_core::plan::StepKind::Command { .. }),
        "{:?}",
        s.kind
    );
    if discky_core::tools::tool_path("hf").is_none() {
        assert!(s.flags.contains(discky_core::plan::StepFlags::TOOL_MISSING));
        assert_eq!(s.warnings, ["hf not found. pip install -U huggingface_hub"]);
    }
}
