//! The scan controller: starts and cancels scans, pumps their events to the UI at most
//! every 100 ms, and watches the snapshot file for scans written by the other process.
//!
//! The watcher polls the file's header every 2 s instead of using kqueue: the snapshot is
//! replaced by a rename, which a vnode watcher on the old file misses. Cost: one small read
//! per 2 s.

use std::sync::Arc;
use std::time::{Duration, Instant};

use discky_core::fs::walk::Progress;
use discky_core::index::snapshot::{Actor, SnapshotMeta};
use discky_core::{Engine, ScanEvent, ScanId, ScanSink, ScanStatus};
use gpui_kit::*;
use smol::channel::{Receiver, TryRecvError};

use crate::app::AppState;

/// How often the pump applies a running scan's events.
const PUMP_INTERVAL: Duration = Duration::from_millis(100);
/// How often the watcher reads the snapshot file's header.
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// Where the controller's scan is.
#[derive(Clone, Debug, PartialEq)]
pub enum ScanPhase {
    /// No scan started from this window yet.
    Idle,
    /// A scan is running; its `Finished` event has not been applied yet.
    Running { id: ScanId },
    /// The last scan's terminal status (`Done`, `Failed` or `Cancelled`).
    Finished(ScanStatus),
}

/// What the controller tells its subscribers; emitted after its own state changed.
#[derive(Clone, Debug)]
pub enum ScanMsg {
    /// The running scan's latest totals.
    Progress(Progress),
    /// The scan ended; on `Done` the engine already serves the new snapshot.
    Finished(ScanStatus),
    /// The snapshot was reloaded from disk: every view should re-read it.
    Refreshed,
    /// The snapshot file is newer than ours and was written by the other process.
    SnapshotUpdatedElsewhere(SnapshotMeta),
}

/// Owns the app's scan: start, cancel, progress, and the snapshot-file watcher.
pub struct ScanController {
    pub phase: ScanPhase,
    /// The running (or last) scan's latest totals.
    pub progress: Progress,
    /// When the running scan started; `None` when none runs.
    pub started_at: Option<Instant>,
    /// The snapshot file's header when it is newer than ours and written by the other actor.
    pub updated_elsewhere: Option<SnapshotMeta>,
    engine: Arc<Engine>,
    /// Applies the running scan's events; dropping it stops the pump.
    _pump: Option<Task<()>>,
    /// Reloads the snapshot off the main thread.
    _reload: Option<Task<()>>,
    /// Polls the snapshot file every [`WATCH_INTERVAL`].
    _watcher: Task<()>,
}

impl EventEmitter<ScanMsg> for ScanController {}

impl ScanController {
    /// A controller for the engine in [`AppState`]; starts the snapshot-file poll.
    pub fn new(cx: &mut Context<Self>) -> Self {
        let engine = Arc::clone(&cx.global::<AppState>().engine);
        let watched = Arc::clone(&engine);
        let watcher = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(WATCH_INTERVAL).await;
                let Ok(running) = this.read_with(cx, |c, _| c.is_running()) else {
                    break;
                };
                // Our own scan writes the file; that write is not "elsewhere".
                if running {
                    continue;
                }
                let engine = Arc::clone(&watched);
                let on_disk = cx
                    .background_executor()
                    .spawn(async move { engine.snapshot_file_meta() })
                    .await;
                let ours = watched.snapshot().map(|s| s.meta.clone());
                let applied = this.update(cx, |c, cx| c.apply_file_meta(ours, on_disk, cx));
                if applied.is_err() {
                    break;
                }
            }
        });
        ScanController {
            phase: ScanPhase::Idle,
            progress: Progress::default(),
            started_at: None,
            updated_elsewhere: None,
            engine,
            _pump: None,
            _reload: None,
            _watcher: watcher,
        }
    }

    /// Whether a scan started here is still running.
    pub fn is_running(&self) -> bool {
        matches!(self.phase, ScanPhase::Running { .. })
    }

    /// Start a scan of the configured roots (or join the one already running) and pump its
    /// events. Does nothing while a scan started here is running.
    pub fn start(&mut self, cx: &mut Context<Self>) {
        if self.is_running() {
            return;
        }
        let (tx, rx) = smol::channel::unbounded::<ScanEvent>();
        // Never panics: a panicking sink would fail the scan. An unbounded send never blocks.
        let sink: ScanSink = Arc::new(move |e| {
            let _ = tx.send_blocking(e);
        });
        let id = self.engine.start_scan_with(None, Some(sink));
        self.phase = ScanPhase::Running { id };
        self.progress = Progress::default();
        self.started_at = Some(Instant::now());
        // Our scan supersedes whatever the other process wrote.
        self.updated_elsewhere = None;
        self._pump = Some(cx.spawn(async move |this, cx| pump(rx, this, cx).await));
        cx.notify();
    }

    /// Ask the running scan to stop; its `Cancelled` arrives through the pump.
    pub fn cancel(&mut self, cx: &mut Context<Self>) {
        if let ScanPhase::Running { id } = &self.phase {
            self.engine.cancel_scan(id);
            cx.notify();
        }
    }

    /// Load the snapshot file written elsewhere (off the main thread), clear the banner and
    /// emit [`ScanMsg::Refreshed`].
    pub fn reload_from_disk(&mut self, cx: &mut Context<Self>) {
        let engine = Arc::clone(&self.engine);
        self._reload = Some(cx.spawn(async move |this, cx| {
            let reloaded = cx
                .background_executor()
                .spawn(async move { engine.reload_snapshot() })
                .await;
            if let Err(e) = reloaded {
                eprintln!("Discky cannot reload the snapshot: {e}");
            }
            // Gone only while the app quits.
            let _ = this.update(cx, |c, cx| {
                c.updated_elsewhere = None;
                cx.emit(ScanMsg::Refreshed);
                cx.notify();
            });
        }));
    }

    /// How long the running scan has run; zero when none runs.
    pub fn elapsed(&self) -> Duration {
        self.started_at.map_or(Duration::ZERO, |t| t.elapsed())
    }

    /// Apply one pump tick: the latest totals and the terminal status, if any.
    fn apply(
        &mut self,
        progress: Option<Progress>,
        finished: Option<ScanStatus>,
        cx: &mut Context<Self>,
    ) {
        if progress.is_none() && finished.is_none() {
            return;
        }
        if let Some(p) = progress {
            self.progress = p.clone();
            cx.emit(ScanMsg::Progress(p));
        }
        if let Some(status) = finished {
            self.phase = ScanPhase::Finished(status.clone());
            self.started_at = None;
            self._pump = None;
            cx.emit(ScanMsg::Finished(status));
        }
        cx.notify();
    }

    /// Show or clear the "updated elsewhere" banner for the file header `on_disk`.
    fn apply_file_meta(
        &mut self,
        ours: Option<SnapshotMeta>,
        on_disk: Option<SnapshotMeta>,
        cx: &mut Context<Self>,
    ) {
        // A scan started while the header was read; its write is ours.
        if self.is_running() {
            return;
        }
        let elsewhere = on_disk.filter(|d| newer_elsewhere(ours.as_ref(), Some(d), Actor::App));
        if elsewhere == self.updated_elsewhere {
            return;
        }
        self.updated_elsewhere = elsewhere.clone();
        if let Some(meta) = elsewhere {
            cx.emit(ScanMsg::SnapshotUpdatedElsewhere(meta));
        }
        cx.notify();
    }
}

/// Apply the events from `rx` to the controller every [`PUMP_INTERVAL`] until the scan's
/// `Finished` (or the controller is gone).
async fn pump(rx: Receiver<ScanEvent>, this: WeakEntity<ScanController>, cx: &mut AsyncApp) {
    loop {
        cx.background_executor().timer(PUMP_INTERVAL).await;
        let mut events = Vec::new();
        let closed = loop {
            match rx.try_recv() {
                Ok(e) => events.push(e),
                Err(TryRecvError::Empty) => break false,
                Err(TryRecvError::Closed) => break true,
            }
        };
        let (progress, mut finished) = coalesce(events);
        // The engine drops the sink only after `Finished`; never stay "running" forever.
        if closed && finished.is_none() {
            finished = Some(ScanStatus::Failed {
                error: "The scan ended without a result.".into(),
            });
        }
        let done = finished.is_some();
        let applied = this.update(cx, |c, cx| c.apply(progress, finished, cx));
        if applied.is_err() || done {
            break;
        }
    }
}

/// The last `Progress` and the first `Finished` among `events`, in arrival order.
pub fn coalesce(events: Vec<ScanEvent>) -> (Option<Progress>, Option<ScanStatus>) {
    let mut progress = None;
    let mut finished = None;
    for e in events {
        match e {
            ScanEvent::Progress(p) => progress = Some(p),
            ScanEvent::Finished(s) => {
                if finished.is_none() {
                    finished = Some(s);
                }
            }
        }
    }
    (progress, finished)
}

/// Whether the snapshot file `on_disk` was written by the other actor (not `me`) after
/// `ours`, the snapshot in memory (or there is none).
pub fn newer_elsewhere(
    ours: Option<&SnapshotMeta>,
    on_disk: Option<&SnapshotMeta>,
    me: Actor,
) -> bool {
    on_disk.is_some_and(|d| d.actor != me && ours.is_none_or(|o| d.created_at > o.created_at))
}

#[cfg(test)]
mod tests {
    // Not `use super::*`: the GPUI glob brings a `test` attribute macro that shadows std's.
    use super::{coalesce, newer_elsewhere};
    use discky_core::fs::walk::Progress;
    use discky_core::index::snapshot::{Actor, SNAPSHOT_FORMAT, SnapshotMeta};
    use discky_core::{ScanEvent, ScanStatus};

    fn progress(files: u64) -> Progress {
        Progress {
            files,
            dirs: files / 10,
            allocated: files * 4096,
            current: None,
        }
    }

    fn meta(created_at: i64, actor: Actor) -> SnapshotMeta {
        SnapshotMeta {
            format_version: SNAPSHOT_FORMAT,
            created_at,
            actor,
            roots: Vec::new(),
            no_access: Vec::new(),
            node_count: 1,
            exact_private_size: false,
        }
    }

    #[test]
    fn coalesce_keeps_last_progress_and_first_finished() {
        assert_eq!(coalesce(Vec::new()), (None, None));

        let (p, s) = coalesce(vec![
            ScanEvent::Progress(progress(1)),
            ScanEvent::Progress(progress(2)),
            ScanEvent::Progress(progress(3)),
        ]);
        assert_eq!(p, Some(progress(3)));
        assert_eq!(s, None);

        let cancelled = ScanStatus::Cancelled {
            finished_at: 10,
            duration_ms: 5,
        };
        let (p, s) = coalesce(vec![
            ScanEvent::Progress(progress(1)),
            ScanEvent::Finished(cancelled.clone()),
            ScanEvent::Progress(progress(7)),
            ScanEvent::Finished(ScanStatus::Failed {
                error: "late".into(),
            }),
        ]);
        assert_eq!(p, Some(progress(7)));
        assert_eq!(s, Some(cancelled));

        let (p, s) = coalesce(vec![ScanEvent::Finished(ScanStatus::Failed {
            error: "boom".into(),
        })]);
        assert_eq!(p, None);
        assert_eq!(
            s,
            Some(ScanStatus::Failed {
                error: "boom".into()
            })
        );
    }

    #[test]
    fn newer_elsewhere_ignores_own_actor_and_older_files() {
        let ours = meta(100, Actor::App);
        // No file: nothing to show.
        assert!(!newer_elsewhere(Some(&ours), None, Actor::App));
        assert!(!newer_elsewhere(None, None, Actor::App));
        // Newer, from the other process.
        assert!(newer_elsewhere(
            Some(&ours),
            Some(&meta(101, Actor::Mcp)),
            Actor::App
        ));
        // No snapshot in memory: any file from the other process is newer.
        assert!(newer_elsewhere(
            None,
            Some(&meta(1, Actor::Mcp)),
            Actor::App
        ));
        // Our own write.
        assert!(!newer_elsewhere(
            Some(&ours),
            Some(&meta(200, Actor::App)),
            Actor::App
        ));
        assert!(!newer_elsewhere(
            None,
            Some(&meta(200, Actor::App)),
            Actor::App
        ));
        // Same or older file from the other process: already loaded or superseded.
        assert!(!newer_elsewhere(
            Some(&ours),
            Some(&meta(100, Actor::Mcp)),
            Actor::App
        ));
        assert!(!newer_elsewhere(
            Some(&ours),
            Some(&meta(99, Actor::Mcp)),
            Actor::App
        ));
        // The same rule from the server's side.
        assert!(newer_elsewhere(
            Some(&meta(100, Actor::Mcp)),
            Some(&meta(150, Actor::App)),
            Actor::Mcp
        ));
    }
}
