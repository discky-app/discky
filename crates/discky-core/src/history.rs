//! The removal log: one JSON line per executed plan step, appended by the executor
//! before it moves on to the next step.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::DisckyPaths;
use crate::index::snapshot::Actor;
use crate::plan::PlanId;
use crate::plan::execute::StepStatus;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRecord {
    /// Unix seconds.
    pub ts: i64,
    pub actor: Actor,
    pub plan: PlanId,
    pub step: usize,
    /// `quit`, `trash`, `remove`, `command` or `ollama_delete`.
    pub kind: String,
    pub paths: Vec<PathBuf>,
    pub argv: Option<Vec<String>>,
    pub status: StepStatus,
    pub freed: u64,
    pub output_tail: String,
    /// For trash steps, `~/.Trash/<basename>` per path: where the item is expected to
    /// be (the Trash may rename it on a name collision).
    pub trash_paths: Vec<PathBuf>,
}

/// The log opened for appending, its parent directories created.
pub(crate) fn open_log(paths: &DisckyPaths) -> io::Result<File> {
    if let Some(dir) = paths.log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
}

/// Append `rec` as one JSON line to `paths.log`.
pub fn append(paths: &DisckyPaths, rec: &HistoryRecord) -> io::Result<()> {
    let mut line = serde_json::to_string(rec).map_err(io::Error::other)?;
    line.push('\n');
    open_log(paths)?.write_all(line.as_bytes())
}

/// Up to `limit` records, newest first. A missing log is empty; lines that do not parse
/// (e.g. a write cut short) are skipped.
pub fn read(paths: &DisckyPaths, limit: usize) -> io::Result<Vec<HistoryRecord>> {
    let mut all = read_all(paths)?;
    all.reverse();
    all.truncate(limit);
    Ok(all)
}

fn read_all(paths: &DisckyPaths) -> io::Result<Vec<HistoryRecord>> {
    let file = match File::open(&paths.log) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        if let Ok(rec) = serde_json::from_str(&line?) {
            out.push(rec);
        }
    }
    Ok(out)
}

/// Recorded `trash_paths` that still exist, oldest record first, each once, with their
/// current allocated size.
pub fn in_trash(paths: &DisckyPaths) -> io::Result<Vec<(PathBuf, u64)>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for rec in read_all(paths)? {
        for p in rec.trash_paths {
            if std::fs::symlink_metadata(&p).is_ok() && seen.insert(p.clone()) {
                let size = allocated(&p);
                out.push((p, size));
            }
        }
    }
    Ok(out)
}

/// `st_blocks * 512` summed over `path` and, for a directory, everything below it
/// (`lstat`, symlinks not followed; unreadable entries count as 0).
fn allocated(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    let own = m.blocks() * 512;
    if !m.is_dir() {
        return own;
    }
    let children = std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| allocated(&e.path()))
        .sum::<u64>();
    own + children
}
