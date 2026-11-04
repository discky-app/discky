//! `cargo xtask scan-gif`: the README scan animation, rendered from the app's own stage
//! ([`discky_app::duck::stage`]) with a scripted scan, into `assets/scan.gif`.
//!
//! The script is fixed and the encoder deterministic, so the committed file can be
//! regenerated and byte-compared in CI, like `assets/logo.png`.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::time::Duration;

use discky_app::duck::fsm::{DuckFsm, State, Thresholds};
use discky_app::duck::sprites::{PALETTE, Sprite, rasterize};
use discky_app::duck::stage::{Canvas, Paint, SCALE, STAGE_H, STAGE_W, Stage};
use gif::{DisposalMethod, Encoder, Frame, Repeat};

/// Device pixels per logical pixel: the GIF is 2x for Retina, shown at 1x width.
const DPR: usize = 2;
/// Time between frames; GIF delays are in 10 ms units, so this is 4 of them (25 fps).
const STEP: Duration = Duration::from_millis(40);
/// How long the closed bin stays before the loop restarts.
const HOLD: Duration = Duration::from_millis(1_000);
/// Longer than any scripted scan: the loop below never spins.
const MAX_FRAMES: usize = 2_000;
/// The ground line: a mid grey that reads on GitHub's light and dark backgrounds.
const GROUND: [u8; 4] = [0x6b, 0x72, 0x80, 0xff];
/// The bin's shadow, darker than the ground.
const SHADOW: [u8; 4] = [0x3f, 0x44, 0x4e, 0xff];
/// The scripted scan's home: paths under it are shown as `~`; nothing is read.
const HOME: &str = "/Users/me";

/// A cumulative progress batch the scripted scan sends at `at`.
struct Batch {
    at: Duration,
    files: u64,
    current: &'static str,
}

/// The scan the duck acts out: two paper trips (2 sheets, then 3), a big subtree that
/// earns the crate, then the scan ends while the crate is shoved in and the lid closes.
///
/// Times are tuned to the walk speeds in `duck/fsm.rs`: the first pick-up happens at
/// once (no grace), the second about 6 s in, and the third trip starts about 6.2 s in,
/// so the big subtree has to be reported before that.
const SCRIPT: &[Batch] = &[
    Batch {
        at: Duration::ZERO,
        files: 3_000,
        current: "/Users/me/Library/Caches/com.apple.dt.Xcode",
    },
    Batch {
        at: Duration::from_millis(3_500),
        files: 40_000,
        current: "/Users/me/Library/Caches/Homebrew",
    },
    Batch {
        at: Duration::from_millis(4_000),
        files: 130_000,
        current: "/Users/me/Library/Developer/Xcode/DerivedData",
    },
];

/// Write `assets/scan.gif` and print its path.
pub fn run(root: &Path) -> Result<(), String> {
    let assets = root.join("assets");
    std::fs::create_dir_all(&assets)
        .map_err(|e| format!("cannot create {}: {e}", assets.display()))?;
    let out = assets.join("scan.gif");
    let frames = render();
    let file = File::create(&out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    encode(BufWriter::new(file), &frames).map_err(|e| format!("cannot encode GIF: {e}"))?;
    println!("wrote {} ({} frames)", out.display(), frames.len());
    Ok(())
}

/// One encoded frame: palette indices (0 = transparent) and how long it shows.
struct GifFrame {
    pixels: Vec<u8>,
    delay: Duration,
}

/// Play [`SCRIPT`] on a fresh state machine and raster every frame; consecutive
/// identical frames are merged into one with the summed delay.
fn render() -> Vec<GifFrame> {
    let mut fsm = DuckFsm::new(Thresholds {
        grace: Duration::ZERO,
        ..Thresholds::default()
    });
    let home = Path::new(HOME);
    let mut frames: Vec<GifFrame> = Vec::new();
    let mut t = Duration::ZERO;
    let mut next = 0;
    let mut finished = false;
    let mut hold = Duration::ZERO;
    for _ in 0..MAX_FRAMES {
        while let Some(b) = SCRIPT.get(next).filter(|b| b.at <= t) {
            let p = discky_core::fs::walk::Progress {
                files: b.files,
                dirs: b.files / 10,
                allocated: b.files * 65_536,
                current: Some(b.current.into()),
            };
            fsm.on_progress(&p, home);
            next += 1;
        }
        if fsm.state == State::Shove && !finished {
            fsm.on_finished();
            finished = true;
        }
        if fsm.state == State::Done {
            if hold >= HOLD {
                break;
            }
            hold += STEP;
        }
        fsm.tick(STEP);
        let mut raster = Raster::new();
        Stage::of(&fsm, false).draw(&mut raster);
        let pixels = raster.indexed();
        match frames.last_mut() {
            Some(last) if last.pixels == pixels => last.delay += STEP,
            _ => frames.push(GifFrame {
                pixels,
                delay: STEP,
            }),
        }
        t += STEP;
    }
    frames
}

/// The GIF's global palette: index 0 is the transparent background, then every sprite
/// colour, the ground and the shadow.
fn palette() -> Vec<[u8; 4]> {
    let mut v = vec![[0, 0, 0, 0]];
    v.extend(PALETTE.iter().map(|(_, c)| *c));
    v.push(GROUND);
    v.push(SHADOW);
    v
}

/// An RGBA stage at [`DPR`] device pixels per logical pixel.
struct Raster {
    w: usize,
    h: usize,
    px: Vec<[u8; 4]>,
}

impl Raster {
    fn new() -> Self {
        let (w, h) = (STAGE_W as usize * DPR, STAGE_H as usize * DPR);
        Raster {
            w,
            h,
            px: vec![[0, 0, 0, 0]; w * h],
        }
    }

    /// Fill device pixels `x0..x1` x `y0..y1`, clipped to the stage.
    fn fill(&mut self, x0: i64, y0: i64, x1: i64, y1: i64, c: [u8; 4]) {
        let (w, h) = (self.w as i64, self.h as i64);
        for y in y0.max(0)..y1.min(h) {
            for x in x0.max(0)..x1.min(w) {
                self.px[(y * w + x) as usize] = c;
            }
        }
    }

    /// The pixels as indices into [`palette`].
    fn indexed(&self) -> Vec<u8> {
        let index: HashMap<[u8; 4], u8> = palette()
            .into_iter()
            .enumerate()
            .map(|(i, c)| (c, i as u8))
            .collect();
        self.px
            .iter()
            .map(|c| if c[3] == 0 { 0 } else { index[c] })
            .collect()
    }
}

/// Logical pixel coordinate `v` as a device pixel edge.
fn dev(v: f32) -> i64 {
    (v * DPR as f32).round() as i64
}

impl Canvas for Raster {
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, paint: Paint) {
        let c = match paint {
            Paint::Ground => GROUND,
            Paint::Shadow => SHADOW,
            Paint::Rgba(c) => c,
        };
        self.fill(dev(x), dev(y), dev(x + w), dev(y + h), c);
    }

    fn sprite(&mut self, x: f32, y: f32, sprite: &'static Sprite, flip_x: bool) {
        for (i, c) in rasterize(sprite, 1).into_iter().enumerate() {
            let Some(c) = c else { continue };
            let (row, col) = (i / sprite.w, i % sprite.w);
            let col = if flip_x { sprite.w - 1 - col } else { col };
            let (px, py) = (x + col as f32 * SCALE, y + row as f32 * SCALE);
            self.fill(dev(px), dev(py), dev(px + SCALE), dev(py + SCALE), c);
        }
    }
}

/// Encode `frames` as a looping GIF with the global [`palette`]; every frame is a full
/// stage restored to transparent before the next one.
fn encode<W: std::io::Write>(w: W, frames: &[GifFrame]) -> Result<(), gif::EncodingError> {
    let (width, height) = (STAGE_W as u16 * DPR as u16, STAGE_H as u16 * DPR as u16);
    let rgb: Vec<u8> = palette().iter().flat_map(|c| [c[0], c[1], c[2]]).collect();
    let mut enc = Encoder::new(w, width, height, &rgb)?;
    enc.set_repeat(Repeat::Infinite)?;
    for f in frames {
        let mut frame = Frame::from_indexed_pixels(width, height, f.pixels.clone(), Some(0));
        frame.delay = (f.delay.as_millis() / 10).min(u128::from(u16::MAX)) as u16;
        frame.dispose = DisposalMethod::Background;
        enc.write_frame(&frame)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use discky_app::duck::sprites::{BLOCK, color};

    #[test]
    fn script_plays_both_paper_stacks_the_crate_and_the_closed_lid() {
        let mut fsm = DuckFsm::new(Thresholds {
            grace: Duration::ZERO,
            ..Thresholds::default()
        });
        let home = Path::new(HOME);
        let mut seen = Vec::new();
        let mut t = Duration::ZERO;
        let mut next = 0;
        let mut finished = false;
        for _ in 0..MAX_FRAMES {
            while let Some(b) = SCRIPT.get(next).filter(|b| b.at <= t) {
                let p = discky_core::fs::walk::Progress {
                    files: b.files,
                    current: Some(b.current.into()),
                    ..Default::default()
                };
                fsm.on_progress(&p, home);
                next += 1;
            }
            if fsm.state == State::Shove && !finished {
                fsm.on_finished();
                finished = true;
            }
            if seen.last() != Some(&fsm.state) {
                seen.push(fsm.state);
            }
            if fsm.state == State::Done {
                break;
            }
            fsm.tick(STEP);
            t += STEP;
        }
        assert_eq!(
            seen,
            [
                State::Hidden,
                State::WalkBack { stack: 2 },
                State::Throw,
                State::WalkOut,
                State::WalkBack { stack: 3 },
                State::Throw,
                State::DragOut,
                State::DragBack,
                State::Shove,
                State::Closing,
                State::Done,
            ]
        );
    }

    #[test]
    fn render_merges_still_frames_and_ends_with_the_hold() {
        let frames = render();
        assert!(frames.len() > 100, "{} frames", frames.len());
        let total: Duration = frames.iter().map(|f| f.delay).sum();
        assert!(
            total > Duration::from_secs(12) && total < Duration::from_secs(20),
            "{total:?}"
        );
        let last = frames.last().unwrap();
        assert!(last.delay >= HOLD, "the closed bin holds: {:?}", last.delay);
        assert!(frames.windows(2).all(|w| w[0].pixels != w[1].pixels));
    }

    #[test]
    fn raster_scales_sprites_and_indexes_the_palette() {
        let mut r = Raster::new();
        r.sprite(8., 4., &BLOCK, false);
        // Sprite pixel (0, 0) covers SCALE * DPR device pixels from (16, 8).
        let outline = color('k').unwrap();
        let side = (SCALE as usize) * DPR;
        for dy in 0..side {
            for dx in 0..side {
                assert_eq!(r.px[(8 + dy) * r.w + 16 + dx], outline);
            }
        }
        assert_eq!(
            r.px[7 * r.w + 16],
            [0, 0, 0, 0],
            "above the sprite stays clear"
        );
        let idx = r.indexed();
        assert_eq!(idx[7 * r.w + 16], 0);
        assert_eq!(
            usize::from(idx[8 * r.w + 16]),
            1 + PALETTE.iter().position(|(k, _)| *k == 'k').unwrap()
        );
    }

    #[test]
    fn rect_clips_to_the_stage() {
        let mut r = Raster::new();
        r.rect(-20., 0., 30., 1., Paint::Ground);
        assert_eq!(r.px[0], GROUND);
        assert_eq!(r.px[dev(10.) as usize - 1], GROUND);
        assert_eq!(r.px[dev(10.) as usize], [0, 0, 0, 0]);
    }

    #[test]
    fn encodes_a_valid_looping_gif() {
        let frames = vec![
            GifFrame {
                pixels: vec![0; STAGE_W as usize * DPR * STAGE_H as usize * DPR],
                delay: Duration::from_millis(40),
            },
            GifFrame {
                pixels: vec![1; STAGE_W as usize * DPR * STAGE_H as usize * DPR],
                delay: Duration::from_millis(1_000),
            },
        ];
        let mut bytes = Vec::new();
        encode(&mut bytes, &frames).unwrap();
        assert!(bytes.starts_with(b"GIF89a"));
        let mut opts = gif::DecodeOptions::new();
        opts.set_color_output(gif::ColorOutput::Indexed);
        let mut dec = opts.read_info(bytes.as_slice()).unwrap();
        assert_eq!((dec.width(), dec.height()), (960, 280));
        assert_eq!(dec.repeat(), Repeat::Infinite);
        let first = dec.read_next_frame().unwrap().unwrap();
        assert_eq!((first.delay, first.transparent), (4, Some(0)));
        let second = dec.read_next_frame().unwrap().unwrap();
        assert_eq!(second.delay, 100);
        assert!(dec.read_next_frame().unwrap().is_none());
    }
}
