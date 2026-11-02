//! Pass 0: model stores. Ollama (API, with an on-disk manifest fallback), the Hugging Face
//! hub, oMLX and LM Studio. Each model is its own finding with its official removal.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Category, Rule, RuleSet, SafetyLabel};

use super::app_caches::unclaimed_sizes;
use super::{Finding, FindingId, Removal, finding_for_node, has_placeholder, node_finding};

const OLLAMA_ID: &str = "ollama-models";
const HF_ID: &str = "hf-hub";
const OMLX_ID: &str = "omlx-models";
const LMSTUDIO_ID: &str = "lmstudio-models";
const DEFAULT_REGISTRY: &str = "registry.ollama.ai";

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("ollama request failed: {0}")]
    Http(String),
    #[error("unexpected ollama response: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OllamaModel {
    pub name: String,
    pub size: u64,
    /// Unix seconds.
    pub modified_at: i64,
    pub digest: String,
    /// Quantization level, else model family, when known.
    pub detail: Option<String>,
}

// --- ollama: HTTP API ---

#[derive(Deserialize)]
struct Tags {
    #[serde(default)]
    models: Vec<TagModel>,
}

#[derive(Deserialize)]
struct TagModel {
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    modified_at: String,
    #[serde(default)]
    digest: String,
    details: Option<TagDetails>,
}

#[derive(Deserialize)]
struct TagDetails {
    quantization_level: Option<String>,
    family: Option<String>,
}

/// `GET {base_url}/api/tags` with 1 s connect and read timeouts.
pub fn ollama_list(base_url: &str) -> Result<Vec<OllamaModel>, ModelError> {
    let timeout = Some(Duration::from_secs(1));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(timeout)
        .timeout_recv_response(timeout)
        .timeout_recv_body(timeout)
        .build()
        .into();
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    let mut resp = agent
        .get(&url)
        .call()
        .map_err(|e| ModelError::Http(e.to_string()))?;
    let tags: Tags = resp
        .body_mut()
        .read_json()
        .map_err(|e| ModelError::Parse(e.to_string()))?;
    Ok(tags
        .models
        .into_iter()
        .map(|m| OllamaModel {
            detail: m.details.and_then(|d| {
                d.quantization_level
                    .filter(|s| !s.is_empty())
                    .or(d.family.filter(|s| !s.is_empty()))
            }),
            modified_at: parse_rfc3339(&m.modified_at).unwrap_or(0),
            name: m.name,
            size: m.size,
            digest: m.digest,
        })
        .collect())
}

/// `2025-10-01T12:34:56.123456789+03:00` to unix seconds.
fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        rest = &frac[frac
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(frac.len())..];
    }
    let offset = match rest.as_bytes().first()? {
        b'Z' | b'z' => 0,
        sign @ (b'+' | b'-') => {
            let oh = rest.get(1..3)?.parse::<i64>().ok()?;
            let om = rest.get(4..6)?.parse::<i64>().ok()?;
            let o = oh * 3600 + om * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

// --- ollama: manifests on disk ---

#[derive(Deserialize)]
struct Blob {
    #[serde(default)]
    size: u64,
    #[serde(default)]
    digest: String,
}

#[derive(Deserialize)]
struct ManifestFile {
    config: Option<Blob>,
    #[serde(default)]
    layers: Vec<Blob>,
}

struct Manifest {
    name: String,
    modified: i64,
    blobs: Vec<(String, u64)>,
}

impl Manifest {
    fn size(&self) -> u64 {
        self.blobs.iter().map(|b| b.1).sum()
    }
}

fn read_manifests(models_dir: &Path) -> Vec<Manifest> {
    let root = models_dir.join("manifests");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file()
                && let Some(m) = read_manifest(&root, &path)
            {
                out.push(m);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn read_manifest(root: &Path, file: &Path) -> Option<Manifest> {
    let parsed: ManifestFile = serde_json::from_slice(&std::fs::read(file).ok()?).ok()?;
    let comps: Vec<String> = file
        .strip_prefix(root)
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let [registry @ .., ns, name, tag] = comps.as_slice() else {
        return None;
    };
    let mut full = String::new();
    if !(registry.len() == 1 && registry[0] == DEFAULT_REGISTRY) {
        full.push_str(&registry.join("/"));
        full.push('/');
    }
    if !(ns == "library" && registry.len() == 1 && registry[0] == DEFAULT_REGISTRY) {
        full.push_str(ns);
        full.push('/');
    }
    full.push_str(&format!("{name}:{tag}"));
    let modified = std::fs::metadata(file)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64);
    Some(Manifest {
        name: full,
        modified,
        blobs: parsed
            .config
            .into_iter()
            .chain(parsed.layers)
            .map(|b| (b.digest, b.size))
            .collect(),
    })
}

/// Models found by walking `manifests/<registry>/<ns>/<name>/<tag>`; for when the server is
/// down. A model's size is its config plus all layers.
pub fn ollama_list_from_manifests(models_dir: &Path) -> Vec<OllamaModel> {
    read_manifests(models_dir)
        .into_iter()
        .map(|m| OllamaModel {
            size: m.size(),
            name: m.name,
            modified_at: m.modified,
            digest: String::new(),
            detail: None,
        })
        .collect()
}

/// Bytes of blobs referenced by `model` and by no other manifest. `None` when the model has
/// no readable manifest.
fn exclusive_bytes(manifests: &[Manifest], model: &str) -> Option<u64> {
    let mine = manifests.iter().find(|m| m.name == model)?;
    let mut users: HashMap<&str, usize> = HashMap::new();
    for m in manifests {
        for d in m.blobs.iter().map(|b| b.0.as_str()).collect::<HashSet<_>>() {
            *users.entry(d).or_default() += 1;
        }
    }
    let mut seen = HashSet::new();
    Some(
        mine.blobs
            .iter()
            .filter(|(d, _)| users.get(d.as_str()) == Some(&1) && seen.insert(d.as_str()))
            .map(|b| b.1)
            .sum(),
    )
}

fn ollama_finding(m: &OllamaModel, manifests: &[Manifest]) -> Finding {
    let mut flags = Vec::new();
    let freed = match exclusive_bytes(manifests, &m.name) {
        Some(f) => {
            if f < m.size {
                flags.push("shared-blobs".to_string());
            }
            f.min(m.size)
        }
        None => {
            flags.push("shared-blobs-unknown".to_string());
            m.size
        }
    };
    Finding {
        id: FindingId::new("ollama", &m.name),
        category: Category::Models,
        title: m.name.clone(),
        subtitle: Some(match &m.detail {
            Some(d) => format!("ollama · {d}"),
            None => "ollama".to_string(),
        }),
        path: None,
        node: None,
        allocated: m.size,
        logical: m.size,
        freed_if_deleted: freed,
        modified: Some(m.modified_at),
        label: SafetyLabel::AppData,
        rule_id: OLLAMA_ID.to_string(),
        explain: "Ollama model. Removed with the Ollama API (same as `ollama rm`); blobs shared with other models stay.".to_string(),
        removal: Removal::OllamaDelete {
            model: m.name.clone(),
        },
        flags,
    }
}

// --- Hugging Face ---

/// One repo directory of a hub cache.
struct HfItem {
    /// Shown to the user, e.g. `org/name` or `dataset org/name`.
    title: String,
    /// Argument for `hf cache rm`, e.g. `org/name` or `datasets/org/name`.
    repo_arg: String,
    path: PathBuf,
}

/// Every `models--`, `datasets--` and `spaces--` dir; `org--name` becomes `org/name`, and a
/// repo without an org keeps just its name.
fn hf_items(hub_dir: &Path) -> Vec<HfItem> {
    let Ok(rd) = std::fs::read_dir(hub_dir) else {
        return Vec::new();
    };
    let mut out: Vec<_> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let (kind, rest) = [
                ("models", ""),
                ("datasets", "dataset "),
                ("spaces", "space "),
            ]
            .into_iter()
            .find_map(|(k, label)| {
                name.strip_prefix(&format!("{k}--"))
                    .map(|r| ((k, label), r))
            })?;
            let repo = rest.replacen("--", "/", 1);
            if repo.is_empty() {
                return None;
            }
            let repo_arg = if kind.0 == "models" {
                repo.clone()
            } else {
                format!("{}/{repo}", kind.0)
            };
            Some(HfItem {
                title: format!("{}{repo}", kind.1),
                repo_arg,
                path: e.path(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Model repos in a hub cache: dirs named `models--org--name` give `org/name`.
pub fn hf_repos(hub_dir: &Path) -> Vec<(String, PathBuf)> {
    hf_items(hub_dir)
        .into_iter()
        .filter(|i| !i.title.contains(' '))
        .map(|i| (i.repo_arg, i.path))
        .collect()
}

fn hub_dirs(home: &Path) -> Vec<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let mut dirs = Vec::new();
    if let Some(d) = env("HF_HUB_CACHE") {
        dirs.push(d);
    }
    if let Some(d) = env("HF_HOME") {
        dirs.push(d.join("hub"));
    }
    dirs.push(home.join(".cache/huggingface/hub"));
    let mut seen = HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

// TODO(task-9): replace with tools::tool_path
fn tool_on_path(name: &str, home: &Path) -> bool {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend([home.join(".local/bin"), PathBuf::from("/opt/homebrew/bin")]);
    dirs.iter().any(|d| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(d.join(name))
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

fn hf_finding(
    index: &Index,
    node: NodeId,
    item: &HfItem,
    rule: Option<&Rule>,
    hf_installed: bool,
) -> Finding {
    let mut f = node_finding(
        index,
        node,
        item.path.clone(),
        Category::Models,
        SafetyLabel::AppData,
        HF_ID,
    );
    f.title = item.title.clone();
    f.subtitle = Some("Hugging Face hub".to_string());
    f.explain = "Downloaded Hugging Face repository. It can be downloaded again.".to_string();
    if let (Some(cmd), true) = (rule.and_then(|r| r.command.as_ref()), hf_installed) {
        let argv: Vec<String> = cmd
            .argv
            .iter()
            .map(|a| a.replace("{repo}", &item.repo_arg))
            .collect();
        if !has_placeholder(&argv) {
            f.removal = Removal::Command {
                tool: cmd.tool.clone(),
                argv,
                cwd: None,
                install_hint: cmd.install_hint.clone(),
                freed_note: None,
            };
        }
    }
    f
}

// --- oMLX / LM Studio ---

/// One `Trash` finding for the dir `node`, described by `rule`.
fn dir_finding(index: &Index, node: NodeId, title: String, rule: &Rule) -> Finding {
    let mut f = finding_for_node(index, node, rule, None);
    f.removal = Removal::Trash {
        paths: vec![index.path(node)],
    };
    f.title = title;
    f
}

fn child_dirs(index: &Index, id: NodeId) -> Vec<NodeId> {
    index
        .children(id)
        .filter(|&c| index.node(c).kind == ObjKind::Dir)
        .collect()
}

fn name_of(index: &Index, id: NodeId) -> String {
    index.name(id).to_string_lossy().into_owned()
}

// --- the pass ---

const MIB: u64 = 1024 * 1024;

/// "Other data in <store>" for what the per-item findings of store `root` do not cover.
/// `reported` are the nodes already reported below `root`; `extra` bytes (allocated and
/// logical) are subtracted on top, for findings that have no node (Ollama). `None` when less
/// than 1 MiB is left.
fn residual_finding(
    index: &Index,
    root: NodeId,
    reported: &HashSet<NodeId>,
    extra: u64,
    store: &str,
    rule_id: &str,
) -> Option<Finding> {
    let (allocated, logical, private) = unclaimed_sizes(index, reported, root);
    let (allocated, logical, private) = (
        allocated.saturating_sub(extra),
        logical.saturating_sub(extra),
        private.saturating_sub(extra),
    );
    if allocated < MIB {
        return None;
    }
    let path = index.path(root);
    let mut f = node_finding(
        index,
        root,
        path.clone(),
        Category::Models,
        SafetyLabel::AppData,
        &format!("{rule_id}:residual"),
    );
    f.id = FindingId::new("residual", &path.to_string_lossy());
    f.title = format!("Other data in {store}");
    f.subtitle = Some(path.to_string_lossy().into_owned());
    f.allocated = allocated;
    f.logical = logical;
    f.freed_if_deleted = private;
    f.removal = Removal::None;
    f.explain = "Not attributable to a single model (orphan blobs, lock files, loose files or unreadable manifests). Inspect it in the disk map before removing anything.".to_string();
    Some(f)
}

/// Model findings: per-model Ollama, Hugging Face, oMLX and LM Studio entries, plus one
/// "Other data in <store>" finding per store for what they do not cover (at least 1 MiB).
/// Each store root found in the index is claimed after it is processed, so the generic rule
/// pass does not report it again.
///
/// For Ollama the findings have no node, so the residual is the root's bytes minus the sum
/// of the models' `freed_if_deleted` (an approximation: blobs shared between models count
/// once there).
pub fn find(
    index: &Index,
    rules: &RuleSet,
    home: &Path,
    ollama_url: &str,
    claimed: &mut HashSet<NodeId>,
) -> Vec<Finding> {
    let mut out = Vec::new();

    let ollama_dir = home.join(".ollama/models");
    if let Some(node) = index.find(&ollama_dir) {
        let manifests = read_manifests(&ollama_dir);
        let models = ollama_list(ollama_url)
            .ok()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| ollama_list_from_manifests(&ollama_dir));
        if models.is_empty() {
            if let Some(rule) = rules.get(OLLAMA_ID) {
                out.push(finding_for_node(index, node, rule, None));
            }
            claimed.insert(node);
        } else {
            let findings: Vec<_> = models
                .iter()
                .map(|m| ollama_finding(m, &manifests))
                .collect();
            let covered = findings.iter().map(|f| f.freed_if_deleted).sum();
            out.extend(findings);
            out.extend(residual_finding(
                index,
                node,
                &HashSet::new(),
                covered,
                "Ollama",
                OLLAMA_ID,
            ));
            claimed.insert(node);
        }
    }

    let hf_rule = rules.get(HF_ID);
    let hf_installed = tool_on_path("hf", home);
    for hub in hub_dirs(home) {
        let Some(root) = index.find(&hub) else {
            continue;
        };
        let mut reported = HashSet::new();
        for item in hf_items(&hub) {
            if let Some(n) = index.find(&item.path) {
                reported.insert(n);
                out.push(hf_finding(index, n, &item, hf_rule, hf_installed));
            }
        }
        out.extend(residual_finding(
            index,
            root,
            &reported,
            0,
            "Hugging Face hub",
            HF_ID,
        ));
        claimed.insert(root);
    }

    if let (Some(root), Some(rule)) = (index.find(&home.join(".omlx/models")), rules.get(OMLX_ID)) {
        let mut reported = HashSet::new();
        for n in child_dirs(index, root) {
            reported.insert(n);
            out.push(dir_finding(index, n, name_of(index, n), rule));
        }
        out.extend(residual_finding(index, root, &reported, 0, "oMLX", OMLX_ID));
        claimed.insert(root);
    }

    if let (Some(root), Some(rule)) = (
        index.find(&home.join(".lmstudio/models")),
        rules.get(LMSTUDIO_ID),
    ) {
        let mut reported = HashSet::new();
        for publisher in child_dirs(index, root) {
            for n in child_dirs(index, publisher) {
                let title = format!("{}/{}", name_of(index, publisher), name_of(index, n));
                reported.insert(n);
                out.push(dir_finding(index, n, title, rule));
            }
        }
        out.extend(residual_finding(
            index,
            root,
            &reported,
            0,
            "LM Studio",
            LMSTUDIO_ID,
        ));
        claimed.insert(root);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::walk::{ScanOptions, walk};

    #[test]
    fn hf_finding_never_carries_a_placeholder() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("models--o--n");
        std::fs::create_dir_all(&repo).unwrap();
        let idx = walk(
            &ScanOptions {
                roots: vec![d.path().into()],
                exclude: globset::GlobSet::empty(),
                threads: 0,
                exact_private_size: false,
            },
            &|_| {},
        );
        let toml = |argv: &str| {
            format!(
                "[[rule]]\nid = \"hf-hub\"\ncategory = \"models\"\nlabel = \"regenerates\"\ntitle = \"t\"\nexplain = \"x\"\nper_child = true\n[rule.matcher]\nkind = \"path\"\npath = \"/nonexistent\"\n[rule.command]\ntool = \"hf\"\nargv = {argv}\n"
            )
        };
        let item = HfItem {
            title: "o/n".into(),
            repo_arg: "o/n".into(),
            path: repo.clone(),
        };
        let node = idx.find(&repo).unwrap();
        let bad = RuleSet::from_toml(&toml(r#"["hf", "rm", "{repo}", "{other}"]"#)).unwrap();
        let f = hf_finding(&idx, node, &item, bad.get("hf-hub"), true);
        assert!(
            matches!(f.removal, Removal::Trash { .. }),
            "{:?}",
            f.removal
        );
        let ok = RuleSet::from_toml(&toml(r#"["hf", "rm", "{repo}"]"#)).unwrap();
        let f = hf_finding(&idx, node, &item, ok.get("hf-hub"), true);
        assert!(matches!(&f.removal, Removal::Command { argv, .. } if argv[2] == "o/n"));
    }

    #[test]
    fn rfc3339_to_unix_seconds() {
        assert_eq!(
            parse_rfc3339("2026-10-23T23:55:30.761459933+03:00"),
            Some(1792788930)
        );
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("garbage"), None);
    }
}
