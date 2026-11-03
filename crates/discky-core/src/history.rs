//! The removal log: one JSON line per executed plan step, appended by the executor
//! before it moves on to the next step.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::DisckyPaths;
use crate::index::snapshot::Actor;
use crate::plan::execute::StepStatus;
use crate::plan::{PlanId, Step, StepKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRecord {
    /// Unix seconds.
    pub ts: i64,
    pub actor: Actor,
    pub plan: PlanId,
    pub step: usize,
    /// `quit`, `trash`, `remove`, `command`, `ollama_delete`, or `interrupted` (see
    /// [`append_interrupted`]).
    pub kind: String,
    pub paths: Vec<PathBuf>,
    pub argv: Option<Vec<String>>,
    pub status: StepStatus,
    pub freed: u64,
    pub output_tail: String,
    /// For trash steps, `~/.Trash/<basename>` per path: where the item is expected to
    /// be (the Trash may rename it on a name collision).
    pub trash_paths: Vec<PathBuf>,
    /// Why the step was skipped or failed, or a note such as "already absent".
    #[serde(default)]
    pub reason: Option<String>,
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
    let mut f = open_log(paths)?;
    f.write_all(line.as_bytes())?;
    f.sync_data()
}

/// Why an [`append_interrupted`] record exists.
pub const INTERRUPTED_REASON: &str = "Interrupted: Discky quit while this step was running";

/// Record that `step` of `plan` was running when the process quit (Dock Quit, logout,
/// restart): kind `interrupted`, status `Failed`, nothing freed. Whether the step's paths
/// are gone is unknown; the next scan tells.
pub fn append_interrupted(
    paths: &DisckyPaths,
    plan: &PlanId,
    step: &Step,
    actor: Actor,
) -> io::Result<()> {
    let (step_paths, argv) = match &step.kind {
        StepKind::Trash { paths } | StepKind::Remove { paths } => (paths.clone(), None),
        StepKind::Command { argv, .. } => (
            step.fingerprints.iter().map(|f| f.path.clone()).collect(),
            Some(argv.clone()),
        ),
        StepKind::Quit { .. } | StepKind::OllamaDelete { .. } => (Vec::new(), None),
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    append(
        paths,
        &HistoryRecord {
            ts,
            actor,
            plan: plan.clone(),
            step: step.index,
            kind: "interrupted".to_string(),
            paths: step_paths,
            argv,
            status: StepStatus::Failed,
            freed: 0,
            output_tail: String::new(),
            trash_paths: Vec::new(),
            reason: Some(INTERRUPTED_REASON.to_string()),
        },
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingId;
    use crate::plan::{Step, StepFlags, StepKind};

    #[test]
    fn append_interrupted_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let paths = DisckyPaths {
            config: d.path().join("config.toml"),
            snapshot: d.path().join("snapshot.bin"),
            log: d.path().join("logs").join("removals.log"),
        };
        let step = Step {
            index: 2,
            finding: FindingId("f".into()),
            description: String::new(),
            kind: StepKind::Remove {
                paths: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            },
            freed: Some(10),
            freed_note: None,
            flags: StepFlags::empty(),
            warnings: vec![],
            fingerprints: vec![],
        };
        append_interrupted(&paths, &PlanId("p1".into()), &step, Actor::App).unwrap();
        let recs = read(&paths, 10).unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.kind, "interrupted");
        assert_eq!(r.status, StepStatus::Failed);
        assert_eq!(r.plan, PlanId("p1".into()));
        assert_eq!(r.step, 2);
        assert_eq!(r.actor, Actor::App);
        assert_eq!(r.paths, [PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]);
        assert_eq!(r.freed, 0);
        assert!(r.trash_paths.is_empty());
        assert_eq!(
            r.reason.as_deref(),
            Some("Interrupted: Discky quit while this step was running")
        );
    }
}
