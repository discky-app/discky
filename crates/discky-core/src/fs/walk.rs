//! Parallel scanner: rayon workers list directories with `getattrlistbulk`, one builder
//! thread (the caller's) appends every listing to the [`Index`] arena and schedules the
//! subdirectories it finds.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use globset::GlobSet;

use crate::fs::attr::{EF_MAY_SHARE_BLOCKS, ObjKind, RawEntry, is_sparse, read_dir_bulk_on_dev};
use crate::fs::dataless::{is_dataless, set_no_materialize};
use crate::index::{Index, Node, NodeFlags, NodeId, ScanError};

/// Directories never descended into, whatever the roots (spec §5).
const SKIP_DIRS: [&str; 3] = ["/System", "/private/var/vm", "/Volumes"];
const PROGRESS_EVERY: Duration = Duration::from_millis(50);

pub struct ScanOptions {
    /// Absolute paths, stored in the index as given; a root that is itself a symlink is
    /// resolved with `canonicalize` and stored resolved.
    pub roots: Vec<PathBuf>,
    /// Matched against full paths; a match is left out of the index entirely.
    pub exclude: GlobSet,
    /// Worker threads; 0 = twice `available_parallelism`. Listing is I/O-latency bound, so
    /// 2× cores measured ~15 % faster on a 4 M-file home than 1×.
    pub threads: usize,
    /// `false` (fast mode) is clone-aware only; blocks held by APFS snapshots are not
    /// subtracted — the Engine enables exact mode when local snapshots exist. `true` asks
    /// the kernel for PRIVATESIZE on every entry, at about twice the listing cost.
    pub exact_private_size: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub files: u64,
    pub dirs: u64,
    pub allocated: u64,
    /// The directory most recently enumerated.
    pub current: Option<PathBuf>,
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// One directory's listing, sent from a worker to the builder.
struct Listing {
    dir: NodeId,
    path: PathBuf,
    dev: u64,
    /// `Ok(None)`: the directory is on another volume (a mount point) and was not listed.
    result: io::Result<Option<Vec<RawEntry>>>,
}

/// Scan `opts.roots` into an [`Index`]. Never fails: unreadable paths are flagged
/// `NO_ACCESS` and listed in `Index::errors`. `on_progress` runs on the calling thread at
/// most every 50 ms.
pub fn walk(opts: &ScanOptions, on_progress: &(dyn Fn(&Progress) + Sync)) -> Index {
    // Best effort: without it a dataless file could be downloaded if touched, but the
    // walker never opens dataless entries anyway.
    let _ = set_no_materialize();
    let threads = match opts.threads {
        0 => 2 * std::thread::available_parallelism().map_or(4, |n| n.get()),
        n => n,
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("create scan thread pool");

    let mut b = Builder {
        index: Index {
            scanned_at: unix_now(),
            ..Index::default()
        },
        exclude: &opts.exclude,
        seen_links: HashSet::new(),
        progress: Progress::default(),
        last_progress: Instant::now(),
    };
    let exact = opts.exact_private_size;
    let (tx, rx) = channel::<Listing>();
    pool.in_place_scope(|s| {
        let mut pending = 0usize;
        for root in &opts.roots {
            if let Some((id, path, dev)) = b.add_root(root) {
                spawn_list(s, &tx, id, path, dev, exact);
                pending += 1;
            }
        }
        while pending > 0 {
            let listing = rx.recv().expect("workers hold a sender until they reply");
            pending -= 1;
            for (id, path, dev) in b.add_listing(listing) {
                spawn_list(s, &tx, id, path, dev, exact);
                pending += 1;
            }
            if b.last_progress.elapsed() >= PROGRESS_EVERY {
                on_progress(&b.progress);
                b.last_progress = Instant::now();
            }
        }
    });
    // Final totals, so even a scan shorter than one interval reports once.
    on_progress(&b.progress);
    b.index.compute_aggregates();
    b.index
}

fn spawn_list<'s>(
    s: &rayon::Scope<'s>,
    tx: &Sender<Listing>,
    dir: NodeId,
    path: PathBuf,
    dev: u64,
    exact: bool,
) {
    let tx = tx.clone();
    s.spawn(move |_| {
        // A panic must still produce a reply, or the builder would wait for it forever.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            BUF.with_borrow_mut(|buf| read_dir_bulk_on_dev(&path, dev, exact, buf))
        }))
        .unwrap_or_else(|_| Err(io::Error::other("directory listing panicked")));
        // The builder outlives every worker, so the receiver is still there.
        let _ = tx.send(Listing {
            dir,
            path,
            dev,
            result,
        });
    });
}

struct Builder<'a> {
    index: Index,
    exclude: &'a GlobSet,
    /// `(st_dev, file_id)` of multiply-linked files already counted.
    seen_links: HashSet<(u64, u64)>,
    progress: Progress,
    last_progress: Instant,
}

impl Builder<'_> {
    /// Append a root node; returns its id, path and device when it is a directory to list.
    /// A root that is itself a symlink is replaced by its `canonicalize`d target.
    fn add_root(&mut self, root: &Path) -> Option<(NodeId, PathBuf, u64)> {
        let id = self.next_id();
        let resolved = match std::fs::symlink_metadata(root) {
            Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(root),
            Ok(_) => Ok(root.to_path_buf()),
            Err(e) => Err(e),
        };
        let (path, meta) = match resolved {
            Ok(p) => {
                let m = std::fs::symlink_metadata(&p);
                (p, m)
            }
            Err(e) => (root.to_path_buf(), Err(e)),
        };
        let name = path.file_name().unwrap_or(path.as_os_str()).as_bytes();
        let mut node = self.new_node(None, name, ObjKind::Dir);
        node.flags = NodeFlags::ROOT;
        let result = match meta {
            Ok(m) => {
                let ft = m.file_type();
                node.kind = if ft.is_dir() {
                    ObjKind::Dir
                } else if ft.is_file() {
                    ObjKind::File
                } else {
                    ObjKind::Other
                };
                node.mtime = m.mtime();
                if node.kind != ObjKind::Dir {
                    node.logical = m.len();
                    node.allocated = m.blocks() * 512;
                    node.private = node.allocated;
                }
                (node.kind == ObjKind::Dir).then(|| (id, path.clone(), m.dev()))
            }
            Err(e) => {
                node.flags |= NodeFlags::NO_ACCESS;
                self.index.errors.push(ScanError {
                    path: root.to_path_buf(),
                    errno: errno(&e),
                });
                None
            }
        };
        self.index.nodes.push(node);
        self.index.roots.push(id);
        self.index.root_paths.push(path);
        result
    }

    /// Append one directory's entries as its children; returns the subdirectories to list.
    fn add_listing(&mut self, l: Listing) -> Vec<(NodeId, PathBuf, u64)> {
        self.progress.dirs += 1;
        let mut path = l.path;
        let entries = match l.result {
            Ok(Some(entries)) => entries,
            Ok(None) => Vec::new(),
            Err(e) => {
                self.node_mut(l.dir).flags |= NodeFlags::NO_ACCESS;
                self.index.errors.push(ScanError {
                    path: path.clone(),
                    errno: errno(&e),
                });
                Vec::new()
            }
        };
        let first = self.index.nodes.len();
        let mut descend = Vec::new();
        for e in entries {
            path.push(&e.name);
            if !self.exclude.is_empty() && self.exclude.is_match(&path) {
                path.pop();
                continue;
            }
            let id = self.next_id();
            if id.0 as usize > first {
                self.index.nodes[id.0 as usize - 1].next_sibling = Some(id);
            }
            if self.add_entry(l.dir, l.dev, &e, &path) {
                descend.push((id, path.clone(), l.dev));
            }
            path.pop();
        }
        if self.index.nodes.len() > first {
            self.node_mut(l.dir).first_child = Some(NodeId(first as u32));
        }
        self.progress.current = Some(path);
        descend
    }

    /// Append the node for `e` (whose full path is `path`); true when it should be listed.
    fn add_entry(&mut self, parent: NodeId, dev: u64, e: &RawEntry, path: &Path) -> bool {
        let mut node = self.new_node(Some(parent), e.name.as_bytes(), e.kind);
        node.mtime = e.mtime;
        if let Some(errno) = e.error {
            node.flags |= NodeFlags::NO_ACCESS;
            self.index.errors.push(ScanError {
                path: path.to_path_buf(),
                errno,
            });
            self.index.nodes.push(node);
            return false;
        }
        node.logical = e.logical;
        node.allocated = e.allocated;
        node.private = e.private.unwrap_or(e.allocated);

        if e.ext_flags.is_some_and(|f| f & EF_MAY_SHARE_BLOCKS != 0) {
            node.flags |= NodeFlags::CLONE_SHARED;
        }
        let dataless = is_dataless(e.bsd_flags);
        if !dataless && is_sparse(e.logical, e.allocated) {
            node.flags |= NodeFlags::SPARSE;
        }
        let dup =
            e.kind != ObjKind::Dir && e.link_count > 1 && !self.seen_links.insert((dev, e.file_id));
        if dataless {
            node.flags |= NodeFlags::DATALESS;
        }
        if dup {
            node.flags |= NodeFlags::HARDLINK_DUP;
        }
        if dataless || dup {
            node.allocated = 0;
            node.private = 0;
        }
        if e.kind != ObjKind::Dir {
            self.progress.files += 1;
        }
        self.progress.allocated += node.allocated;
        self.index.nodes.push(node);
        e.kind == ObjKind::Dir && !dataless && !SKIP_DIRS.iter().any(|s| path == Path::new(s))
    }

    fn new_node(&mut self, parent: Option<NodeId>, name: &[u8], kind: ObjKind) -> Node {
        let off = self.index.names.len() as u32;
        let len = name.len().min(u16::MAX as usize);
        self.index.names.extend_from_slice(&name[..len]);
        Node {
            parent,
            name: (off, len as u16),
            kind,
            logical: 0,
            allocated: 0,
            private: 0,
            mtime: 0,
            flags: NodeFlags::empty(),
            first_child: None,
            next_sibling: None,
            agg_allocated: 0,
            agg_private: 0,
            agg_logical: 0,
            agg_files: 0,
            max_mtime: 0,
        }
    }

    fn next_id(&self) -> NodeId {
        NodeId(self.index.nodes.len() as u32)
    }

    fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.index.nodes[id.0 as usize]
    }
}

fn errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
