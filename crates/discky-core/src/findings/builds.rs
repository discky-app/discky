//! Pass 2: project build directories (`target/` next to `Cargo.toml`, …).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Matcher, Rule, RuleSet};

use super::{Finding, finding_for_node, home_dirs, walk_unclaimed};

/// Home-relative trees whose build-like dirs belong to tools, not user projects.
const EXCLUDED: [&str; 4] = ["Library", ".vscode", ".cursor", ".npm/_npx"];

/// One finding per unclaimed directory named like a `BuildDir` rule's `name` whose parent
/// holds the rule's `marker`; the first matching rule (file order) wins. The command, if
/// any, runs in the project dir. `modified` is the project's newest mtime outside the
/// build dir, so a fresh build does not make an abandoned project look active.
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
    if by_name.is_empty() {
        return Vec::new();
    }
    let excluded = home_dirs(home, &EXCLUDED);
    let mut out = Vec::new();
    let mut hits = Vec::new();
    walk_unclaimed(index, claimed, |id, path| {
        let node = index.node(id);
        if node.kind != ObjKind::Dir || excluded.iter().any(|e| path.starts_with(e)) {
            return false;
        }
        let (Some(parent), Some(candidates)) = (
            node.parent,
            index.name(id).to_str().and_then(|n| by_name.get(n)),
        ) else {
            return true;
        };
        let hit = candidates
            .iter()
            .find(|(_, marker)| index.children(parent).any(|c| index.name(c) == *marker));
        match hit {
            Some(&(rule, _)) => {
                let cwd = path.parent().map(Path::to_path_buf);
                let mut f = finding_for_node(index, id, rule, cwd);
                f.modified = Some(project_mtime(index, parent, id));
                hits.push(id);
                out.push(f);
                false
            }
            None => true,
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
