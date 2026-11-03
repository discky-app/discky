//! Pass 2: per-app folders directly under `~/Library` (caches, app data, containers, logs).

use std::collections::HashSet;
use std::path::Path;

use crate::fs::attr::ObjKind;
use crate::index::{Index, NodeId};
use crate::rules::{Category, SafetyLabel};

use super::{Finding, node_finding};

const MIB: u64 = 1024 * 1024;

/// `(parent dir under ~/Library, label, explanation)`.
pub const PARENTS: [(&str, SafetyLabel, &str); 8] = [
    (
        "Caches",
        SafetyLabel::Regenerates,
        "Cache data the app can rebuild. Safe to remove; the app may start slower once.",
    ),
    (
        "Application Support",
        SafetyLabel::AppData,
        "App data and settings. Removing it resets the app; keep it unless the app is gone.",
    ),
    (
        "Group Containers",
        SafetyLabel::AppData,
        "Data shared between an app and its extensions. Removing it resets the app.",
    ),
    (
        "Containers",
        SafetyLabel::AppData,
        "Sandboxed app data. Removing it resets the app.",
    ),
    (
        "HTTPStorages",
        SafetyLabel::Regenerates,
        "Web caches and cookies the app recreates.",
    ),
    (
        "WebKit",
        SafetyLabel::Regenerates,
        "Web caches and cookies the app recreates.",
    ),
    (
        "Saved Application State",
        SafetyLabel::Regenerates,
        "Window state restored at launch. Safe to remove.",
    ),
    (
        "Logs",
        SafetyLabel::Regenerates,
        "Log files. Safe to remove.",
    ),
];

/// Who owns a `~/Library` subfolder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerHint {
    pub bundle_id: Option<String>,
    pub app_name: String,
}

/// Owner of the folder `dir_name` inside `~/Library/<container_parent>`. Bundle-id style
/// names yield the title-cased last component (`com.openai.codex` is "Codex"); for
/// `Application Support` and `Logs` the folder name is the app name.
pub fn owner_of(container_parent: &str, dir_name: &str) -> OwnerHint {
    match container_parent {
        "Application Support" | "Logs" => OwnerHint {
            bundle_id: None,
            app_name: dir_name.to_string(),
        },
        "Group Containers" => {
            let mut s = dir_name;
            if let Some((team, rest)) = s.split_once('.')
                && team.len() == 10
                && team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                s = rest;
            }
            s = s.strip_prefix("group.").unwrap_or(s);
            for suffix in [".shared", ".group"] {
                s = s.strip_suffix(suffix).unwrap_or(s);
            }
            hint_from_bundle(s)
        }
        _ => hint_from_bundle(dir_name.strip_suffix(".savedState").unwrap_or(dir_name)),
    }
}

fn hint_from_bundle(id: &str) -> OwnerHint {
    let last = id.rsplit('.').next().unwrap_or(id);
    let mut chars = last.chars();
    let app_name = chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default();
    OwnerHint {
        bundle_id: id.contains('.').then(|| id.to_string()),
        app_name,
    }
}

/// One finding per direct child directory of the `~/Library` folders in [`PARENTS`] that
/// is at least 1 MiB allocated once descendants claimed by earlier passes are subtracted.
/// Each finding claims its directory. Children already claimed are skipped.
pub fn find(index: &Index, home: &Path, claimed: &mut HashSet<NodeId>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (parent, label, explain) in PARENTS {
        let Some(parent_id) = index.find(&home.join("Library").join(parent)) else {
            continue;
        };
        let slug = format!("app-cache:{}", parent.to_lowercase().replace(' ', "-"));
        let children: Vec<NodeId> = index
            .children(parent_id)
            .filter(|&c| index.node(c).kind == ObjKind::Dir)
            .collect();
        for id in children {
            if super::is_claimed(index, claimed, id) {
                continue;
            }
            let (allocated, logical, private) = unclaimed_sizes(index, claimed, id);
            if allocated < MIB {
                continue;
            }
            let dir_name = index.name(id).to_string_lossy().into_owned();
            let mut f = node_finding(index, id, index.path(id), Category::AppCaches, label, &slug);
            f.title = owner_of(parent, &dir_name).app_name;
            f.subtitle = Some(format!("{parent} · {dir_name}"));
            f.explain = explain.to_string();
            f.allocated = allocated;
            f.logical = logical;
            f.freed_if_deleted = private;
            claimed.insert(id);
            out.push(f);
        }
    }
    out
}

/// `(allocated, logical, private)` of directory `id` minus claimed descendants.
pub(super) fn unclaimed_sizes(
    index: &Index,
    claimed: &HashSet<NodeId>,
    id: NodeId,
) -> (u64, u64, u64) {
    let n = index.node(id);
    let mut sizes = (n.agg_allocated, n.agg_logical, n.agg_private);
    let mut stack = vec![id];
    while let Some(cur) = stack.pop() {
        for c in index.children(cur) {
            let cn = index.node(c);
            if claimed.contains(&c) {
                let (a, l, p) = if cn.kind == ObjKind::Dir {
                    (cn.agg_allocated, cn.agg_logical, cn.agg_private)
                } else {
                    (cn.allocated, cn.logical, cn.private)
                };
                sizes.0 = sizes.0.saturating_sub(a);
                sizes.1 = sizes.1.saturating_sub(l);
                sizes.2 = sizes.2.saturating_sub(p);
            } else if cn.kind == ObjKind::Dir {
                stack.push(c);
            }
        }
    }
    sizes
}
