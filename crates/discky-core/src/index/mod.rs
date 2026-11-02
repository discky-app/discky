//! In-memory scan result: a flat arena of nodes with first-child / next-sibling links.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::fs::attr::ObjKind;

pub mod snapshot;

/// Position of a node in [`Index::nodes`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct NodeFlags: u16 {
        /// `allocated` far below `logical` (see `fs::attr::is_sparse`).
        const SPARSE = 1 << 0;
        /// Contents evicted to the cloud; never opened, counted with `allocated = 0`.
        const DATALESS = 1 << 1;
        /// Second or later name of a hard-linked file; its blocks are counted elsewhere.
        const HARDLINK_DUP = 1 << 2;
        /// The entry or directory could not be read; contents unknown. See `Index::errors`.
        const NO_ACCESS = 1 << 3;
        /// APFS reports the file may share blocks with a clone.
        const CLONE_SHARED = 1 << 4;
        /// A scan root.
        const ROOT = 1 << 5;
    }
}

/// One filesystem object. `agg_*` and `max_mtime` cover the node itself plus everything
/// below it (a file's aggregates are its own values, with `agg_files = 1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub parent: Option<NodeId>,
    /// `(offset, len)` into [`Index::names`].
    pub name: (u32, u16),
    pub kind: ObjKind,
    pub logical: u64,
    /// Bytes on disk; 0 for dataless files and hard-link duplicates.
    pub allocated: u64,
    /// Bytes freed if deleted (APFS private size, else `allocated`).
    pub private: u64,
    pub mtime: i64,
    pub flags: NodeFlags,
    pub first_child: Option<NodeId>,
    pub next_sibling: Option<NodeId>,
    pub agg_allocated: u64,
    pub agg_private: u64,
    pub agg_logical: u64,
    /// Number of non-directory nodes in the subtree.
    pub agg_files: u32,
    pub max_mtime: i64,
}

/// A path the scan could not read, with the OS error number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub errno: i32,
}

/// The whole scan. Children always have larger ids than their parent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub nodes: Vec<Node>,
    pub names: Vec<u8>,
    pub roots: Vec<NodeId>,
    /// Full path of each root as scanned, parallel to `roots`.
    pub root_paths: Vec<PathBuf>,
    /// Unix seconds when the scan started.
    pub scanned_at: i64,
    pub errors: Vec<ScanError>,
}

impl Index {
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.0 as usize]
    }

    /// The node's own name (for a root: the last component of its path).
    pub fn name(&self, id: NodeId) -> &OsStr {
        let (off, len) = self.node(id).name;
        OsStr::from_bytes(&self.names[off as usize..off as usize + len as usize])
    }

    /// Absolute path: the root's stored path joined with the names below it.
    pub fn path(&self, id: NodeId) -> PathBuf {
        let mut chain = Vec::new();
        let mut cur = id;
        while let Some(parent) = self.node(cur).parent {
            chain.push(cur);
            cur = parent;
        }
        let root = self.roots.iter().position(|&r| r == cur);
        let mut path = root.map_or_else(PathBuf::new, |i| self.root_paths[i].clone());
        for &n in chain.iter().rev() {
            path.push(self.name(n));
        }
        path
    }

    pub fn children(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        std::iter::successors(self.node(id).first_child, |&c| self.node(c).next_sibling)
    }

    /// Look up `path` by components below the first root whose path is a prefix of it.
    pub fn find(&self, path: &Path) -> Option<NodeId> {
        self.roots
            .iter()
            .zip(&self.root_paths)
            .find_map(|(&root, root_path)| {
                let rest = path.strip_prefix(root_path).ok()?;
                rest.components().try_fold(root, |cur, c| match c {
                    Component::Normal(name) => self.children(cur).find(|&ch| self.name(ch) == name),
                    Component::CurDir => Some(cur),
                    _ => None,
                })
            })
    }

    /// Bytes on disk under all roots.
    pub fn total_allocated(&self) -> u64 {
        self.roots.iter().map(|&r| self.node(r).agg_allocated).sum()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Fill `agg_*` and `max_mtime` bottom-up. Relies on children having larger ids.
    pub(crate) fn compute_aggregates(&mut self) {
        for n in &mut self.nodes {
            n.agg_allocated = n.allocated;
            n.agg_private = n.private;
            n.agg_logical = n.logical;
            n.agg_files = u32::from(n.kind != ObjKind::Dir);
            n.max_mtime = n.mtime;
        }
        for i in (0..self.nodes.len()).rev() {
            let n = &self.nodes[i];
            let Some(p) = n.parent else { continue };
            let (a, pr, l, f, m) = (
                n.agg_allocated,
                n.agg_private,
                n.agg_logical,
                n.agg_files,
                n.max_mtime,
            );
            let p = &mut self.nodes[p.0 as usize];
            p.agg_allocated += a;
            p.agg_private += pr;
            p.agg_logical += l;
            p.agg_files += f;
            p.max_mtime = p.max_mtime.max(m);
        }
    }
}
