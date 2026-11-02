//! Pass 2: project build directories (`target/` next to `Cargo.toml`, …).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Matcher, Rule, RuleSet};

use super::{Finding, Removal, finding_for_node, home_dirs, walk_unclaimed};

/// Home-relative trees whose build-like dirs belong to tools, not user projects: version
/// managers, editors, package-manager stores, toolchains, `~/Library`, `~/Applications`.
const EXCLUDED: [&str; 16] = [
    ".local/share/mise",
    ".nvm",
    ".volta",
    ".bun",
    ".asdf",
    ".vscode",
    ".vscode-insiders",
    ".cursor",
    ".windsurf",
    ".npm",
    ".yarn",
    ".pnpm-store",
    ".cargo",
    ".rustup",
    "Library",
    "Applications",
];

/// Directory-name suffixes of macOS bundles: what is inside is shipped code, not a project.
const BUNDLE_SUFFIXES: [&str; 5] = [".app", ".bundle", ".framework", ".xcframework", ".appex"];

/// One finding per unclaimed directory named like a `BuildDir` rule's `name` whose parent
/// holds the rule's `marker`; the first matching rule (file order) wins. The command, if
/// any, runs in the project dir; `cargo clean` gets `--target-dir <the finding's path>` so
/// it can only remove what was reported. `modified` is the project's newest mtime outside
/// the build dir, so a fresh build does not make an abandoned project look active.
///
/// Only roots at or under `home` are walked (none without a home), never the
/// [`EXCLUDED`] trees, and never below a bundle (`*.app`, `*.bundle`, `*.framework`,
/// `*.xcframework`, `*.appex`) or a `node_modules` directory: build-like dirs there are
/// live code of an app or a package, not leftovers of a user's build.
pub fn find(
    index: &Index,
    rules: &RuleSet,
    home: Option<&Path>,
    claimed: &mut HashSet<NodeId>,
) -> Vec<Finding> {
    let mut by_name: HashMap<&str, Vec<(&Rule, &str)>> = HashMap::new();
    for rule in rules.build_rules() {
        if let Matcher::BuildDir { name, marker } = &rule.matcher {
            by_name.entry(name).or_default().push((rule, marker));
        }
    }
    let Some(home) = home else {
        return Vec::new();
    };
    if by_name.is_empty() {
        return Vec::new();
    }
    let excluded = home_dirs(Some(home), &EXCLUDED);
    let mut out = Vec::new();
    let mut hits = Vec::new();
    walk_unclaimed(index, claimed, |id, path| {
        let node = index.node(id);
        if node.kind != ObjKind::Dir
            || (node.parent.is_none() && !path.starts_with(home))
            || excluded.iter().any(|e| path.starts_with(e))
        {
            return false;
        }
        let name = index.name(id).to_str();
        if name.is_some_and(|n| BUNDLE_SUFFIXES.iter().any(|s| n.ends_with(s))) {
            return false;
        }
        let (Some(parent), Some(candidates)) = (node.parent, name.and_then(|n| by_name.get(n)))
        else {
            return name != Some("node_modules");
        };
        let hit = candidates
            .iter()
            .find(|(_, marker)| index.children(parent).any(|c| index.name(c) == *marker));
        match hit {
            Some(&(rule, _)) => {
                let cwd = path.parent().map(Path::to_path_buf);
                let mut f = finding_for_node(index, id, rule, cwd);
                if let Removal::Command { argv, .. } = &mut f.removal
                    && argv.len() == 2
                    && argv[0] == "cargo"
                    && argv[1] == "clean"
                {
                    argv.extend([
                        "--target-dir".to_string(),
                        path.to_string_lossy().into_owned(),
                    ]);
                }
                f.modified = Some(project_mtime(index, parent, id));
                hits.push(id);
                out.push(f);
                false
            }
            None => name != Some("node_modules"),
        }
    });
    claimed.extend(hits);
    out
}

/// Newest mtime of `project` and everything in it except the `build` subtree.
fn project_mtime(index: &Index, project: NodeId, build: NodeId) -> i64 {
    index
        .children(project)
        .filter(|&c| c != build)
        .map(|c| index.node(c).max_mtime)
        .fold(index.node(project).mtime, i64::max)
}
