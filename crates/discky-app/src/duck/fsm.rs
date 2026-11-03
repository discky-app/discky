//! The robo-duck state machine, driven by scan progress (spec §11a).
//!
//! Pure: no clock reads and no GPUI. The caller feeds progress batches via
//! [`DuckFsm::on_progress`], the end of the scan via [`DuckFsm::on_finished`]
//! and elapsed time via [`DuckFsm::tick`]; the renderer reads `state`, `x`,
//! `frame`, `bin_open` and the pose helpers.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use discky_core::fs::walk::Progress;

use super::sprites::{Pose, frames};

/// Where the duck turns around off-stage (left of the visible stage).
const OFF_X: f32 = -0.15;
/// The bin's position on the stage.
pub const BIN_X: f32 = 0.85;
/// Stage widths per second while walking.
const WALK_SPEED: f32 = 0.35;
/// Stage widths per second while dragging the crate.
const DRAG_SPEED: f32 = 0.2;
/// One animation frame of a walk cycle.
const FRAME: Duration = Duration::from_millis(125);
/// The throw takes two frames.
const THROW: Duration = Duration::from_millis(250);
/// The shove takes three frames.
const SHOVE: Duration = Duration::from_millis(600);
/// The lid closes over this long before the scene ends.
const CLOSING: Duration = Duration::from_millis(600);
/// Walking/dragging speed multiplier once the scan has finished.
///
/// Worst case from `on_finished` to `Done` (the duck at the turn point, x = -0.15):
/// - walk trip: 1.0 stage / 1.4 per s = 0.71 s + throw 0.25 s + closing 0.6 s = 1.56 s;
/// - drag trip: 1.0 stage / 0.8 per s = 1.25 s + shove 0.6 s + closing 0.6 s = 2.45 s.
const FINISH_SPEEDUP: f32 = 4.0;

/// Where the scene is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    /// Nothing shown yet (no progress, or still inside the grace period).
    Hidden,
    /// Walking left, empty-handed, to fetch the next batch.
    WalkOut,
    /// Walking right to the bin carrying `stack` (1..=3) paper sheets.
    WalkBack {
        /// Paper stack size, see [`stack_for`].
        stack: u8,
    },
    /// Tossing the papers into the bin.
    Throw,
    /// Walking left to fetch the crate of a big subtree.
    DragOut,
    /// Pulling the crate to the bin on a rope, slower.
    DragBack,
    /// Pushing the crate into the bin.
    Shove,
    /// The scan ended; the bin lid closes.
    Closing,
    /// The scene is over (or never started).
    Done,
}

/// When a subtree counts as big, and how long a scan must run to show the duck.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thresholds {
    /// Files under one subtree that make it big.
    pub big_files: u64,
    /// Allocated bytes under one subtree that make it big.
    pub big_bytes: u64,
    /// Scans that finish sooner than this show nothing.
    pub grace: Duration,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            big_files: 50_000,
            big_bytes: 2 * 1024 * 1024 * 1024,
            grace: Duration::from_millis(1_500),
        }
    }
}

/// The robo-duck scene: one trip per progress batch, a crate for a big subtree.
#[derive(Clone, Debug)]
pub struct DuckFsm {
    /// The current state.
    pub state: State,
    /// The duck's position across the stage, `0..1` (below 0 is off-stage left).
    pub x: f32,
    /// Index into `frames(self.pose())`.
    pub frame: usize,
    /// Whether the bin lid is open.
    pub bin_open: bool,
    th: Thresholds,
    /// The first progress arrived; the grace clock runs.
    started: bool,
    /// Time since the first progress (only counted while `Hidden`).
    waited: Duration,
    /// Time in the current timed state, or towards the next walk frame.
    clock: Duration,
    /// `on_finished` arrived: hurry to the bin at [`FINISH_SPEEDUP`], then close.
    finishing: bool,
    /// Latest cumulative counters.
    files: u64,
    allocated: u64,
    /// `files` when the previous trip picked up its papers.
    trip_files: u64,
    /// The stack of the last pick-up (shown while throwing).
    last_stack: u8,
    /// Big-subtree tracking: the current key and what accumulated under it.
    key: Option<PathBuf>,
    key_files: u64,
    key_bytes: u64,
    triggered: HashSet<PathBuf>,
    pending_big: bool,
}

/// The key a scan position is accounted under: `home` + 2 components when
/// `current` is inside `home`, otherwise the first 3 components below the
/// root (`/Users/me/Library/Caches/x` -> `/Users/me/Library/Caches`,
/// `/opt/homebrew/Cellar/x` -> `/opt/homebrew/Cellar`).
pub fn subtree_key(current: &Path, home: &Path) -> PathBuf {
    if let Ok(rest) = current.strip_prefix(home)
        && !home.as_os_str().is_empty()
    {
        let mut key = home.to_path_buf();
        key.extend(rest.components().take(2));
        return key;
    }
    let mut key = PathBuf::new();
    let mut normal = 0;
    for c in current.components() {
        if let Component::Normal(_) = c {
            if normal == OUTSIDE_HOME_DEPTH {
                break;
            }
            normal += 1;
        }
        key.push(c);
    }
    key
}

/// Components kept below the root for a path outside `home`.
const OUTSIDE_HOME_DEPTH: usize = 3;

/// Paper sheets carried for a batch of `files_delta` new files.
pub fn stack_for(files_delta: u64) -> u8 {
    match files_delta {
        0..2_000 => 1,
        2_000..20_000 => 2,
        _ => 3,
    }
}

impl DuckFsm {
    /// A hidden scene waiting for the first progress.
    pub fn new(th: Thresholds) -> Self {
        Self {
            state: State::Hidden,
            x: OFF_X,
            frame: 0,
            bin_open: false,
            th,
            started: false,
            waited: Duration::ZERO,
            clock: Duration::ZERO,
            finishing: false,
            files: 0,
            allocated: 0,
            trip_files: 0,
            last_stack: 1,
            key: None,
            key_files: 0,
            key_bytes: 0,
            triggered: HashSet::new(),
            pending_big: false,
        }
    }

    /// Records a progress batch (cumulative counters) and watches for a big subtree.
    pub fn on_progress(&mut self, p: &Progress, home: &Path) {
        if self.state == State::Done || self.finishing {
            return;
        }
        self.started = true;
        let files = p.files.saturating_sub(self.files);
        let bytes = p.allocated.saturating_sub(self.allocated);
        self.files = self.files.max(p.files);
        self.allocated = self.allocated.max(p.allocated);
        let Some(current) = &p.current else { return };
        let key = subtree_key(current, home);
        if self.key.as_ref() == Some(&key) {
            self.key_files = self.key_files.saturating_add(files);
            self.key_bytes = self.key_bytes.saturating_add(bytes);
        } else {
            self.key = Some(key.clone());
            self.key_files = files;
            self.key_bytes = bytes;
        }
        let big = self.key_files >= self.th.big_files || self.key_bytes >= self.th.big_bytes;
        if big && !self.triggered.contains(&key) {
            self.triggered.insert(key);
            self.pending_big = true;
        }
    }

    /// The scan ended: before the grace period nothing is ever shown;
    /// otherwise the duck hurries to the bin ([`FINISH_SPEEDUP`]), turning
    /// around at once if it was heading away, drops its load and the lid closes.
    pub fn on_finished(&mut self) {
        match self.state {
            State::Hidden => self.enter(State::Done),
            State::Done | State::Closing => {}
            State::WalkOut => {
                self.finishing = true;
                self.last_stack = 1;
                self.enter(State::WalkBack { stack: 1 });
            }
            State::DragOut => {
                self.finishing = true;
                self.enter(State::DragBack);
            }
            _ => self.finishing = true,
        }
    }

    /// Advances the scene by `dt`; returns `true` while the caller should keep
    /// ticking (waiting out the grace period, animating, or the tick that
    /// reached `Done`), `false` before the first progress and once `Done`.
    pub fn tick(&mut self, dt: Duration) -> bool {
        let speedup = if self.finishing { FINISH_SPEEDUP } else { 1.0 };
        let secs = dt.as_secs_f32() * speedup;
        match self.state {
            State::Hidden => {
                if !self.started {
                    return false;
                }
                self.waited += dt;
                if self.waited >= self.th.grace {
                    self.bin_open = true;
                    self.x = OFF_X;
                    self.pick_up();
                }
            }
            State::WalkOut | State::DragOut => {
                self.advance_frame(dt);
                self.x -= WALK_SPEED * secs;
                if self.x <= OFF_X {
                    self.x = OFF_X;
                    self.pick_up_for(self.state == State::DragOut);
                }
            }
            State::WalkBack { .. } | State::DragBack => {
                let v = if self.state == State::DragBack {
                    DRAG_SPEED
                } else {
                    WALK_SPEED
                };
                self.advance_frame(dt);
                self.x += v * secs;
                if self.x >= BIN_X {
                    self.x = BIN_X;
                    let next = if self.state == State::DragBack {
                        State::Shove
                    } else {
                        State::Throw
                    };
                    self.enter(next);
                }
            }
            State::Throw | State::Shove => {
                let total = if self.state == State::Throw {
                    THROW
                } else {
                    SHOVE
                };
                let n = frames(self.pose()).len();
                self.clock += dt;
                if self.clock >= total {
                    self.next_trip();
                } else {
                    let per = total.as_secs_f32() / n as f32;
                    self.frame = ((self.clock.as_secs_f32() / per) as usize).min(n - 1);
                }
            }
            State::Closing => {
                self.clock += dt;
                if self.clock >= CLOSING {
                    self.enter(State::Done);
                }
            }
            State::Done => return false,
        }
        true
    }

    /// Whether anything should be drawn.
    pub fn visible(&self) -> bool {
        !matches!(self.state, State::Hidden | State::Done)
    }

    /// The animation for the current state.
    pub fn pose(&self) -> Pose {
        match self.state {
            State::Hidden | State::Done => Pose::Idle,
            State::WalkOut | State::DragOut => Pose::Walk,
            State::WalkBack { .. } => Pose::Carry,
            State::DragBack => Pose::Drag,
            State::Throw => Pose::Throw,
            State::Shove => Pose::Shove,
            State::Closing => Pose::Stand,
        }
    }

    /// Paper sheets in hand (`WalkBack`) or in flight (`Throw`); 0 otherwise.
    pub fn stack(&self) -> u8 {
        match self.state {
            State::WalkBack { stack } => stack,
            State::Throw => self.last_stack,
            _ => 0,
        }
    }

    /// Whether the crate is on stage (pulled in `DragBack`, pushed in `Shove`).
    pub fn dragging(&self) -> bool {
        matches!(self.state, State::DragBack | State::Shove)
    }

    /// Off-stage pick-up at the start of the scene: a crate if one is pending.
    fn pick_up(&mut self) {
        let drag = std::mem::take(&mut self.pending_big);
        self.pick_up_for(drag);
    }

    /// Off-stage pick-up: the crate, or papers sized by the files since the last one.
    fn pick_up_for(&mut self, drag: bool) {
        let delta = self.files.saturating_sub(self.trip_files);
        self.trip_files = self.files;
        if drag {
            self.enter(State::DragBack);
        } else {
            self.last_stack = stack_for(delta);
            self.enter(State::WalkBack {
                stack: self.last_stack,
            });
        }
    }

    /// After a throw or shove: close up when finishing, else the next trip.
    fn next_trip(&mut self) {
        if self.finishing {
            self.bin_open = false;
            self.enter(State::Closing);
        } else if std::mem::take(&mut self.pending_big) {
            self.enter(State::DragOut);
        } else {
            self.enter(State::WalkOut);
        }
    }

    fn enter(&mut self, state: State) {
        self.state = state;
        self.frame = 0;
        self.clock = Duration::ZERO;
        if state == State::Done {
            self.bin_open = false;
        }
    }

    fn advance_frame(&mut self, step: Duration) {
        self.clock += step;
        let n = frames(self.pose()).len();
        while self.clock >= FRAME {
            self.clock -= FRAME;
            self.frame = (self.frame + 1) % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discky_core::fs::walk::Progress;
    use std::path::Path;
    use std::time::Duration;

    const HOME: &str = "/Users/me";

    fn progress(files: u64, current: &str) -> Progress {
        Progress {
            files,
            dirs: 0,
            allocated: files * 4096,
            current: Some(current.into()),
        }
    }

    /// Ticks in 10 ms steps for at most `secs`, stopping when `until` holds.
    fn run(fsm: &mut DuckFsm, secs: f32, mut until: impl FnMut(&DuckFsm) -> bool) -> bool {
        let steps = (secs * 100.0) as usize;
        for _ in 0..steps {
            if until(fsm) {
                return true;
            }
            fsm.tick(Duration::from_millis(10));
        }
        until(fsm)
    }

    fn no_big() -> Thresholds {
        Thresholds {
            big_files: u64::MAX,
            big_bytes: u64::MAX,
            ..Thresholds::default()
        }
    }

    /// A scene that is already visible, with `files` counted before the grace ended.
    fn visible_fsm(th: Thresholds, files: u64) -> DuckFsm {
        let mut fsm = DuckFsm::new(th);
        fsm.on_progress(&progress(files, "/Users/me/Documents/a"), Path::new(HOME));
        assert!(run(&mut fsm, 2.0, |f| f.visible()));
        fsm
    }

    #[test]
    fn scene_hidden_before_grace_period() {
        let mut fsm = DuckFsm::new(Thresholds::default());
        assert!(!fsm.visible());
        fsm.on_progress(&progress(10, "/Users/me/a"), Path::new(HOME));
        for _ in 0..14 {
            fsm.tick(Duration::from_millis(100));
        }
        assert!(!fsm.visible(), "1.4 s");
        assert_eq!(fsm.state, State::Hidden);
        fsm.tick(Duration::from_millis(100));
        fsm.tick(Duration::from_millis(100));
        assert!(fsm.visible(), "1.6 s");
    }

    #[test]
    fn finished_before_grace_never_shows() {
        let mut fsm = DuckFsm::new(Thresholds::default());
        fsm.on_progress(&progress(10, "/Users/me/a"), Path::new(HOME));
        for _ in 0..5 {
            fsm.tick(Duration::from_millis(100));
        }
        fsm.on_finished();
        assert_eq!(fsm.state, State::Done);
        assert!(!fsm.visible());
        for _ in 0..30 {
            fsm.tick(Duration::from_millis(100));
        }
        assert!(!fsm.visible());
    }

    #[test]
    fn stack_size_follows_batch() {
        let home = Path::new(HOME);
        // First trip picks up what arrived during the grace period.
        let mut fsm = visible_fsm(no_big(), 500);
        assert_eq!(fsm.state, State::WalkBack { stack: 1 });
        assert_eq!(fsm.stack(), 1);

        fsm.on_progress(&progress(5_500, "/Users/me/Documents/b"), home);
        assert!(run(&mut fsm, 10.0, |f| f.state == State::WalkOut));
        assert!(run(&mut fsm, 10.0, |f| matches!(
            f.state,
            State::WalkBack { .. }
        )));
        assert_eq!(fsm.stack(), 2);

        fsm.on_progress(&progress(65_500, "/Users/me/Movies/c"), home);
        assert!(run(&mut fsm, 10.0, |f| f.state == State::WalkOut));
        assert!(run(&mut fsm, 10.0, |f| matches!(
            f.state,
            State::WalkBack { .. }
        )));
        assert_eq!(fsm.stack(), 3);
    }

    #[test]
    fn big_subtree_triggers_drag_once() {
        let home = Path::new(HOME);
        let mut fsm = visible_fsm(Thresholds::default(), 100);
        assert_eq!(fsm.state, State::WalkBack { stack: 1 });
        // 60 000 files under ~/Library/Caches, in two batches.
        fsm.on_progress(&progress(30_100, "/Users/me/Library/Caches/x/1"), home);
        fsm.on_progress(&progress(60_100, "/Users/me/Library/Caches/y/2"), home);
        assert!(run(&mut fsm, 10.0, |f| f.state != State::WalkBack { stack: 1 }));
        assert!(run(&mut fsm, 10.0, |f| f.state != State::Throw));
        assert_eq!(fsm.state, State::DragOut);
        assert!(run(&mut fsm, 10.0, |f| f.state == State::DragBack));
        assert!(fsm.dragging());
        assert!(run(&mut fsm, 10.0, |f| f.state == State::Shove));

        // A further 60 000 under the same key: no second drag.
        fsm.on_progress(&progress(120_100, "/Users/me/Library/Caches/z/3"), home);
        let mut saw_drag = false;
        let mut trips = 0;
        let mut prev = fsm.state;
        run(&mut fsm, 30.0, |f| {
            if f.state != prev {
                if f.state == State::DragOut {
                    saw_drag = true;
                }
                if f.state == State::WalkOut {
                    trips += 1;
                }
                prev = f.state;
            }
            false
        });
        assert!(trips >= 2, "trips: {trips}");
        assert!(!saw_drag);
    }

    #[test]
    fn finish_closes_bin_then_done() {
        // Worst case for a walk trip: just turned off-stage, heading back.
        let mut fsm = visible_fsm(Thresholds::default(), 100);
        assert!(fsm.bin_open);
        assert!(run(&mut fsm, 10.0, |f| f.state == State::WalkOut));
        assert!(run(&mut fsm, 10.0, |f| f.x < 0.0));
        fsm.on_finished();
        assert_eq!(fsm.state, State::WalkBack { stack: 1 }, "turns around");
        assert!(run(&mut fsm, 2.0, |f| f.state == State::Done));

        // Worst case overall: heading out for a crate, past the stage edge.
        let mut fsm = visible_fsm(Thresholds::default(), 100);
        fsm.on_progress(
            &progress(80_000, "/Users/me/Library/Caches/x"),
            Path::new(HOME),
        );
        assert!(run(&mut fsm, 10.0, |f| f.state == State::DragOut));
        assert!(run(&mut fsm, 10.0, |f| f.x < 0.0));
        fsm.on_finished();
        assert_eq!(fsm.state, State::DragBack, "turns around");
        let mut saw_closing = false;
        // 1.25 s drag + 0.6 s shove + 0.6 s closing = 2.45 s (see FINISH_SPEEDUP).
        let reached = run(&mut fsm, 2.5, |f| {
            saw_closing |= f.state == State::Closing;
            f.state == State::Done
        });
        assert!(reached, "state: {:?}", fsm.state);
        assert!(saw_closing);
        assert!(!fsm.bin_open);
        assert!(!fsm.visible());
    }

    #[test]
    fn frame_stays_within_the_pose() {
        let mut fsm = visible_fsm(Thresholds::default(), 100);
        fsm.on_progress(
            &progress(80_000, "/Users/me/Library/Caches/x"),
            Path::new(HOME),
        );
        let mut fine = true;
        run(&mut fsm, 20.0, |f| {
            fine &= f.frame < crate::duck::sprites::frames(f.pose()).len();
            false
        });
        assert!(fine);
    }

    #[test]
    fn tick_reports_when_to_keep_animating() {
        let mut fsm = DuckFsm::new(Thresholds::default());
        assert!(!fsm.tick(Duration::from_millis(10)), "no progress yet");
        fsm.on_progress(&progress(1, "/Users/me/a"), Path::new(HOME));
        assert!(fsm.tick(Duration::from_millis(10)), "grace clock running");
        fsm.on_finished();
        assert_eq!(fsm.state, State::Done);
        assert!(!fsm.tick(Duration::from_millis(10)));
    }

    #[test]
    fn subtree_key_truncates_to_two_components() {
        let home = Path::new(HOME);
        assert_eq!(
            subtree_key(Path::new("/Users/me/Library/Caches/x/y"), home),
            Path::new("/Users/me/Library/Caches")
        );
        assert_eq!(
            subtree_key(Path::new("/opt/homebrew/Cellar/x"), home),
            Path::new("/opt/homebrew/Cellar")
        );
        assert_eq!(
            subtree_key(Path::new("/Users/me/Music"), home),
            Path::new("/Users/me/Music")
        );
        assert_eq!(subtree_key(Path::new("/opt"), home), Path::new("/opt"));
    }

    #[test]
    fn stack_for_thresholds() {
        assert_eq!(stack_for(0), 1);
        assert_eq!(stack_for(1_999), 1);
        assert_eq!(stack_for(2_000), 2);
        assert_eq!(stack_for(19_999), 2);
        assert_eq!(stack_for(20_000), 3);
        assert_eq!(stack_for(u64::MAX), 3);
    }
}
