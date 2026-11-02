//! Snapshot persistence: the last scan, shared between the GUI and the MCP server.
//!
//! Layout: `b"DISCKY01"`, `u32` LE meta length, postcard(meta), postcard(`Body`).
//! Writers serialize in memory, then hold a write lock on `<path>.lock` while writing
//! a tmp file and renaming it over the target. Readers hold the read lock.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fd_lock::RwLock;
use serde::{Deserialize, Serialize};

use crate::findings::Finding;
use crate::index::Index;

const MAGIC: &[u8; 8] = b"DISCKY01";
pub const SNAPSHOT_FORMAT: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot has an incompatible format")]
    Incompatible,
    #[error("failed to decode snapshot: {0}")]
    Decode(postcard::Error),
    #[error("failed to encode snapshot: {0}")]
    Encode(postcard::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    App,
    Mcp,
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Actor::App => "app",
            Actor::Mcp => "mcp",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub format_version: u32,
    pub created_at: i64,
    pub actor: Actor,
    pub roots: Vec<PathBuf>,
    pub no_access: Vec<PathBuf>,
    pub node_count: u32,
}

#[derive(Debug)]
pub struct Snapshot {
    pub meta: SnapshotMeta,
    pub index: Index,
    pub findings: Vec<Finding>,
}

#[derive(Serialize, Deserialize)]
struct Body {
    index: Index,
    findings: Vec<Finding>,
}

fn lock_file(path: &Path) -> Result<RwLock<File>, SnapshotError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))?;
    Ok(RwLock::new(file))
}

/// Reads and validates magic + meta; leaves the reader positioned at the body.
fn read_header(r: &mut impl Read) -> Result<SnapshotMeta, SnapshotError> {
    let mut head = [0u8; 12];
    r.read_exact(&mut head).map_err(eof_is_incompatible)?;
    if &head[..8] != MAGIC {
        return Err(SnapshotError::Incompatible);
    }
    let len = u32::from_le_bytes(head[8..].try_into().expect("4 bytes")) as usize;
    let mut buf = Vec::new();
    r.take(len as u64).read_to_end(&mut buf)?;
    if buf.len() != len {
        return Err(SnapshotError::Incompatible);
    }
    let meta: SnapshotMeta = postcard::from_bytes(&buf).map_err(SnapshotError::Decode)?;
    if meta.format_version != SNAPSHOT_FORMAT {
        return Err(SnapshotError::Incompatible);
    }
    Ok(meta)
}

fn eof_is_incompatible(e: std::io::Error) -> SnapshotError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        SnapshotError::Incompatible
    } else {
        SnapshotError::Io(e)
    }
}

impl Snapshot {
    pub fn save(&self, path: &Path) -> Result<(), SnapshotError> {
        let meta = postcard::to_stdvec(&self.meta).map_err(SnapshotError::Encode)?;
        let body = postcard::to_stdvec(&BodyRef {
            index: &self.index,
            findings: &self.findings,
        })
        .map_err(SnapshotError::Encode)?;
        let mut bytes = Vec::with_capacity(12 + meta.len() + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&meta);
        bytes.extend_from_slice(&body);

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut lock = lock_file(path)?;
        let _guard = lock.write()?;
        let tmp = path.with_extension("bin.tmp");
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Snapshot, SnapshotError> {
        let lock = lock_file(path)?;
        let _guard = lock.read()?;
        let mut r = std::io::BufReader::new(File::open(path)?);
        let meta = read_header(&mut r)?;
        let mut rest = Vec::new();
        r.read_to_end(&mut rest)?;
        let Body { index, findings } =
            postcard::from_bytes(&rest).map_err(SnapshotError::Decode)?;
        Ok(Snapshot {
            meta,
            index,
            findings,
        })
    }

    pub fn peek_meta(path: &Path) -> Result<SnapshotMeta, SnapshotError> {
        let lock = lock_file(path)?;
        let _guard = lock.read()?;
        read_header(&mut File::open(path)?)
    }
}

/// Borrowing twin of `Body` so `save` need not clone the index.
#[derive(Serialize)]
struct BodyRef<'a> {
    index: &'a Index,
    findings: &'a [Finding],
}
