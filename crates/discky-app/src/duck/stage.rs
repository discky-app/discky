//! One frame of the scan stage, composed without a renderer: the bin, the papers or the
//! crate, the rope and the duck, as rectangles and sprites in stage coordinates.
//!
//! The app paints a [`Stage`] on a GPUI canvas; `cargo xtask scan-gif` rasterizes the
//! same frames into the README animation. Both implement [`Canvas`].

use super::fsm::{BIN_X, DuckFsm, State};
use super::sprites::{self, BIN_CLOSED, BIN_OPEN, BLOCK, Pose, STACK, Sprite, frames};

/// Logical pixels per sprite pixel on the stage.
pub const SCALE: f32 = 4.;
/// Stage size in logical pixels.
pub const STAGE_W: f32 = 480.;
pub const STAGE_H: f32 = 140.;
/// The ground line's top, from the stage's top.
pub const GROUND_Y: f32 = 132.;
/// Where the duck stands with reduced motion, in stage units.
const STILL_X: f32 = BIN_X - 0.15;
/// Gap between the dragged crate and the duck, in sprite pixels.
const ROPE_LEN: f32 = 6.;

/// A colour the stage paints with: a theme colour or a palette RGBA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paint {
    /// The ground line (the theme's border colour in the app).
    Ground,
    /// The bin's shadow (the theme's muted colour in the app).
    Shadow,
    /// A sprite palette colour.
    Rgba([u8; 4]),
}

/// Where a [`Stage`] draws. Coordinates are logical pixels from the stage's top-left
/// corner; sizes of sprites are `SCALE` logical pixels per sprite pixel.
pub trait Canvas {
    /// Fill the `w` x `h` logical-pixel rectangle at (`x`, `y`).
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, paint: Paint);
    /// Paint `sprite` with its top-left corner at (`x`, `y`), `SCALE` logical pixels per
    /// sprite pixel, mirrored when `flip_x`.
    fn sprite(&mut self, x: f32, y: f32, sprite: &'static Sprite, flip_x: bool);
}

/// One frame of the stage.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Stage {
    pub duck: &'static Sprite,
    /// The duck faces left (sprites face right).
    pub flip: bool,
    /// The duck's position in stage units, see [`DuckFsm::x`].
    pub x: f32,
    /// Paper sheets in hand or in flight (0 = none).
    pub stack: u8,
    /// The papers fly into the bin rather than ride on the duck.
    pub throwing: bool,
    /// The crate is on a rope behind the duck.
    pub rope: bool,
    /// The crate drops into the bin; the value is the shove frame.
    pub shove: Option<usize>,
    pub bin_open: bool,
}

impl Stage {
    /// The frame `fsm` shows now; a still duck by the open bin with reduced motion.
    pub fn of(fsm: &DuckFsm, reduce_motion: bool) -> Stage {
        if reduce_motion {
            return Stage {
                duck: &frames(Pose::Stand)[0],
                flip: false,
                x: STILL_X,
                stack: 0,
                throwing: false,
                rope: false,
                shove: None,
                bin_open: true,
            };
        }
        let pose = fsm.pose();
        let poses = frames(pose);
        Stage {
            duck: &poses[fsm.frame.min(poses.len() - 1)],
            flip: matches!(fsm.state, State::WalkOut | State::DragOut),
            x: fsm.x,
            stack: fsm.stack(),
            throwing: fsm.state == State::Throw,
            rope: fsm.dragging() && fsm.state == State::DragBack,
            shove: (fsm.state == State::Shove).then_some(fsm.frame),
            bin_open: fsm.bin_open,
        }
    }

    /// Draw the frame onto `c`, back to front. The caller clips to the stage: the duck
    /// walks in from off-stage.
    pub fn draw(&self, c: &mut impl Canvas) {
        // Ground line and the bin's shadow.
        c.rect(0., GROUND_Y, STAGE_W, 1., Paint::Ground);
        let bin_x = BIN_X * STAGE_W;
        let bin_h = BIN_OPEN.h as f32 * SCALE;
        let bin_top = GROUND_Y - bin_h;
        c.rect(
            bin_x - SCALE,
            GROUND_Y - SCALE / 2.,
            BIN_OPEN.w as f32 * SCALE + 2. * SCALE,
            SCALE,
            Paint::Shadow,
        );
        // The bin's rim row: papers and the crate sink in behind its body.
        let rim = bin_top + 8. * SCALE;
        let bin_mid = bin_x + BIN_OPEN.w as f32 * SCALE / 2.;
        if let Some(frame) = self.shove {
            let side = BLOCK.w as f32 * SCALE;
            let y = rim - side + (frame as f32 + 1.) * side / 4.;
            c.sprite(bin_mid - side / 2., y, &BLOCK, false);
        }
        let stack = usize::from(self.stack.min(3))
            .checked_sub(1)
            .map(|i| &STACK[i]);
        let duck_w = self.duck.w as f32 * SCALE;
        let duck_left = self.x * STAGE_W - duck_w;
        let duck_top = GROUND_Y - self.duck.h as f32 * SCALE;
        if let (Some(s), true) = (stack, self.throwing) {
            let sw = s.w as f32 * SCALE;
            let y = rim - s.h as f32 * SCALE / 2.;
            c.sprite(bin_mid - sw / 2., y, s, false);
        }
        let bin = if self.bin_open {
            &BIN_OPEN
        } else {
            &BIN_CLOSED
        };
        c.sprite(bin_x, bin_top, bin, false);
        if self.rope {
            let side = BLOCK.w as f32 * SCALE;
            let block_right = duck_left - ROPE_LEN * SCALE;
            c.sprite(block_right - side, GROUND_Y - side, &BLOCK, false);
            // The rope leaves the sprite's left edge on its first 'r' row.
            let row = self
                .duck
                .rows
                .iter()
                .position(|r| r.starts_with('r'))
                .unwrap_or(7);
            if let Some(color) = sprites::color('r') {
                let y = duck_top + row as f32 * SCALE;
                c.rect(block_right, y, ROPE_LEN * SCALE, SCALE, Paint::Rgba(color));
            }
        }
        c.sprite(duck_left, duck_top, self.duck, self.flip);
        if let (Some(s), false) = (stack, self.throwing) {
            // Held up over the back: columns 0..8 of the right-facing sprite.
            let col = if self.flip { 8. } else { 0. };
            let y = duck_top - s.h as f32 * SCALE;
            c.sprite(duck_left + col * SCALE, y, s, self.flip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duck::fsm::Thresholds;
    use discky_core::fs::walk::Progress;
    use std::path::Path;
    use std::time::Duration;

    /// Records every draw call.
    #[derive(Default)]
    struct Log {
        rects: Vec<(f32, f32, f32, f32, Paint)>,
        sprites: Vec<(f32, f32, &'static Sprite, bool)>,
    }

    impl Canvas for Log {
        fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, paint: Paint) {
            self.rects.push((x, y, w, h, paint));
        }
        fn sprite(&mut self, x: f32, y: f32, sprite: &'static Sprite, flip_x: bool) {
            self.sprites.push((x, y, sprite, flip_x));
        }
    }

    fn no_big() -> Thresholds {
        Thresholds {
            big_files: u64::MAX,
            big_bytes: u64::MAX,
            grace: Duration::ZERO,
        }
    }

    fn started(th: Thresholds, files: u64) -> DuckFsm {
        let mut fsm = DuckFsm::new(th);
        let p = Progress {
            files,
            allocated: files * 4096,
            current: Some("/Users/me/Library/Caches/x".into()),
            ..Progress::default()
        };
        fsm.on_progress(&p, Path::new("/Users/me"));
        fsm.tick(Duration::from_millis(10));
        fsm
    }

    #[test]
    fn walk_back_draws_ground_bin_duck_and_stack_back_to_front() {
        let fsm = started(no_big(), 5_000);
        assert!(matches!(fsm.state, State::WalkBack { stack: 2 }));
        let stage = Stage::of(&fsm, false);
        let mut log = Log::default();
        stage.draw(&mut log);
        assert_eq!(
            log.rects,
            [
                (0., GROUND_Y, STAGE_W, 1., Paint::Ground),
                (404., 130., 72., 4., Paint::Shadow),
            ],
            "ground, then the bin's shadow; no rope while carrying papers"
        );
        let duck_left = stage.x * STAGE_W - 64.;
        assert_eq!(
            log.sprites,
            [
                (408., 52., &BIN_OPEN, false),
                (duck_left, 68., stage.duck, false),
                (duck_left, 48., &STACK[1], false),
            ],
            "bin, then the duck walking right, then the 2-sheet stack over its back"
        );
    }

    #[test]
    fn shove_drops_the_crate_behind_the_bin() {
        let th = Thresholds {
            big_files: 1,
            ..no_big()
        };
        let mut fsm = started(th, 5_000);
        for _ in 0..1_000 {
            if fsm.state == State::Shove {
                break;
            }
            fsm.tick(Duration::from_millis(10));
        }
        assert_eq!((fsm.state, fsm.frame), (State::Shove, 0));
        let stage = Stage::of(&fsm, false);
        assert!(!stage.rope, "no rope once the crate is at the bin");
        let mut log = Log::default();
        stage.draw(&mut log);
        let duck_left = BIN_X * STAGE_W - 64.;
        assert_eq!(
            log.sprites,
            [
                (416., 48., &BLOCK, false),
                (408., 52., &BIN_OPEN, false),
                (duck_left, 68., stage.duck, false),
            ],
            "the crate is painted first so the bin's body hides it as it sinks"
        );
        fsm.tick(Duration::from_millis(210));
        assert_eq!(fsm.frame, 1);
        let mut later = Log::default();
        Stage::of(&fsm, false).draw(&mut later);
        assert_eq!(
            later.sprites[0].1, 60.,
            "the crate sinks 12 px per shove frame"
        );
    }

    #[test]
    fn drag_back_draws_the_crate_and_the_rope_behind_a_flipped_free_duck() {
        let th = Thresholds {
            big_files: 1,
            ..no_big()
        };
        let fsm = started(th, 5_000);
        assert_eq!(fsm.state, State::DragBack);
        let stage = Stage::of(&fsm, false);
        assert!(stage.rope);
        let mut log = Log::default();
        stage.draw(&mut log);
        let rope = log.rects.iter().find(|r| matches!(r.4, Paint::Rgba(_)));
        assert!(
            rope.is_some(),
            "the rope is painted in the palette's rope colour"
        );
        let block = log.sprites.iter().find(|s| *s.2 == BLOCK);
        let duck_left = stage.x * STAGE_W - stage.duck.w as f32 * SCALE;
        assert_eq!(
            block.map(|s| s.0),
            Some(duck_left - (ROPE_LEN + BLOCK.w as f32) * SCALE),
            "the crate trails the duck by the rope's length"
        );
    }

    #[test]
    fn reduced_motion_is_a_still_duck_by_the_open_bin() {
        let fsm = started(no_big(), 5_000);
        let stage = Stage::of(&fsm, true);
        assert_eq!(stage.duck, &frames(Pose::Stand)[0]);
        assert_eq!((stage.x, stage.stack, stage.bin_open), (STILL_X, 0, true));
        let mut log = Log::default();
        stage.draw(&mut log);
        assert_eq!(log.sprites.len(), 2, "bin and duck only");
    }

    #[test]
    fn closed_bin_after_finish() {
        let mut fsm = started(no_big(), 5_000);
        fsm.on_finished();
        for _ in 0..200 {
            fsm.tick(Duration::from_millis(250));
            if fsm.state == State::Closing {
                break;
            }
        }
        assert_eq!(fsm.state, State::Closing);
        let mut log = Log::default();
        Stage::of(&fsm, false).draw(&mut log);
        assert!(log.sprites.iter().any(|s| *s.2 == BIN_CLOSED));
    }
}
