//! The robo-duck scan animation: pixel sprites, the scan-driven state machine, and
//! the GPUI scene that paints them on a canvas.
//!
//! GPUI scales images with a linear filter only, so sprites are painted pixel by pixel:
//! one `fill` quad per opaque sprite pixel, its edges snapped to device pixels.

pub mod fsm;
pub mod sprites;
pub mod stage;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use discky_core::fs::walk::Progress;
use gpui_kit::component::{ActiveTheme as _, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::format;
use crate::scan::ScanMsg;
use fsm::{DuckFsm, State, Thresholds};
use sprites::{LOGO, Sprite};
use stage::{Canvas, Paint, SCALE, STAGE_H, STAGE_W, Stage};

/// Longest frame step: a window that was in the background does not jump.
const MAX_DT: Duration = Duration::from_millis(250);
/// The longest scan path shown under the stage, in characters.
const PATH_CHARS: usize = 60;

/// The scan scene: the duck carries paper stacks (or drags a crate for a big subtree)
/// into the bin while a scan runs. An entity owned by the Overview; one per scan.
pub struct DuckScene {
    fsm: DuckFsm,
    /// When the scene last advanced; `None` while it waits for progress.
    last_tick: Option<Instant>,
    /// The user's home, for the big-subtree keys and the `~` in the path line.
    /// Empty when unknown: every path then counts as outside home.
    home: PathBuf,
    /// The latest totals, shown under the stage.
    progress: Progress,
}

impl Default for DuckScene {
    fn default() -> Self {
        Self::new()
    }
}

impl DuckScene {
    /// A hidden scene waiting for the scan's first progress.
    pub fn new() -> Self {
        DuckScene {
            fsm: DuckFsm::new(Thresholds::default()),
            last_tick: None,
            home: discky_core::paths::home_dir().unwrap_or_default(),
            progress: Progress::default(),
        }
    }

    /// Feed a controller message: progress drives the trips, `Finished` sends the duck
    /// to the bin and closes the lid. Other messages are not about the scan.
    pub fn apply(&mut self, msg: &ScanMsg, cx: &mut Context<Self>) {
        match msg {
            ScanMsg::Progress(p) => {
                self.fsm.on_progress(p, &self.home);
                self.progress = p.clone();
            }
            ScanMsg::Finished(_) => {
                self.fsm.on_finished();
                // Without animation frames nothing would play the walk to the bin out:
                // with reduced motion the scene ends at once.
                if cx.reduce_motion() {
                    fast_forward(&mut self.fsm);
                }
            }
            ScanMsg::Refreshed
            | ScanMsg::SnapshotUpdatedElsewhere(_)
            | ScanMsg::RefusedDuringRemoval => return,
        }
        cx.notify();
    }

    /// Whether the scene shows (past the grace period, not done yet). The Overview shows
    /// the hero number instead once this turns false after a scan.
    pub fn visible(&self) -> bool {
        self.fsm.visible()
    }

    /// The line under the stage: "1,234,567 files · 212 GB" and the shortened path.
    fn progress_line(&self) -> (String, Option<String>) {
        let p = &self.progress;
        let totals = format!(
            "{} files · {}",
            format::count(p.files),
            format::bytes(p.allocated)
        );
        let path = p.current.as_ref().map(|c| {
            let shown = if self.home.as_os_str().is_empty() {
                c.to_string_lossy().into_owned()
            } else {
                format::home_relative(c, &self.home)
            };
            format::shorten_left(&shown, PATH_CHARS)
        });
        (totals, path)
    }
}

/// Play the state machine out to `Done` in quarter-second steps (bounded).
fn fast_forward(fsm: &mut DuckFsm) {
    for _ in 0..200 {
        if fsm.state == State::Done {
            break;
        }
        fsm.tick(MAX_DT);
    }
}

impl Render for DuckScene {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let now = Instant::now();
        let dt = self
            .last_tick
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t))
            .min(MAX_DT);
        let was_visible = self.fsm.visible();
        let animating = self.fsm.tick(dt);
        self.last_tick = animating.then_some(now);
        let reduce_motion = cx.reduce_motion();
        if animating && !reduce_motion {
            window.request_animation_frame();
        }
        if self.fsm.visible() != was_visible {
            // The Overview swaps the progress line or the hero for the scene; tell it
            // outside this draw.
            cx.on_next_frame(window, |_, _, cx| cx.notify());
        }
        let visible = self.fsm.visible();
        let stage = Stage::of(&self.fsm, reduce_motion);
        let (totals, path) = self.progress_line();
        let theme = cx.theme();
        let (ground, shadow) = (theme.border, theme.muted);
        let muted = theme.muted_foreground;
        let mono = theme.mono_font_family.clone();
        div().when(visible, |this| {
            this.child(
                v_flex()
                    .gap_2()
                    .child(
                        canvas(
                            |_, _, _| (),
                            move |bounds, _, window, _| {
                                paint_stage(stage, bounds, ground, shadow, window)
                            },
                        )
                        .w(px(STAGE_W))
                        .h(px(STAGE_H)),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_1()
                            .text_sm()
                            .text_color(muted)
                            .child(totals)
                            .when_some(path, |this, path| {
                                this.child("·")
                                    .child(div().font_family(mono).truncate().child(path))
                            }),
                    ),
            )
        })
    }
}

/// A GPUI window as the stage's canvas: theme colours for the ground and the shadow,
/// every rectangle snapped to device pixels.
struct GpuiCanvas<'a> {
    window: &'a mut Window,
    origin: Point<Pixels>,
    ground: Hsla,
    shadow: Hsla,
}

impl Canvas for GpuiCanvas<'_> {
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, paint: Paint) {
        let color = match paint {
            Paint::Ground => self.ground,
            Paint::Shadow => self.shadow,
            Paint::Rgba(c) => to_hsla(c),
        };
        let at = point(self.origin.x + px(x), self.origin.y + px(y));
        let quad = snapped(at, w, h, 1., self.window.scale_factor());
        self.window.paint_quad(fill(quad, color));
    }

    fn sprite(&mut self, x: f32, y: f32, sprite: &'static Sprite, flip_x: bool) {
        let at = point(self.origin.x + px(x), self.origin.y + px(y));
        paint_sprite(self.window, at, SCALE, sprite, flip_x);
    }
}

/// Paint `stage` into `bounds` (clipped to it: the duck walks in from off-stage).
fn paint_stage(
    stage: Stage,
    bounds: Bounds<Pixels>,
    ground: Hsla,
    shadow: Hsla,
    window: &mut Window,
) {
    let mask = ContentMask { bounds };
    window.with_content_mask(Some(mask), |window| {
        let mut canvas = GpuiCanvas {
            window,
            origin: bounds.origin,
            ground,
            shadow,
        };
        stage.draw(&mut canvas);
    });
}

/// Paint `sprite` with its top-left corner at `origin`, `scale` logical pixels per
/// sprite pixel, mirrored when `flip_x`: one `fill` quad per opaque pixel, each edge
/// rounded to the nearest device pixel so neighbouring quads meet without seams.
pub fn paint_sprite(
    window: &mut Window,
    origin: Point<Pixels>,
    scale: f32,
    sprite: &Sprite,
    flip_x: bool,
) {
    let sf = window.scale_factor();
    for (i, c) in sprites::rasterize(sprite, 1).into_iter().enumerate() {
        let Some(c) = c else { continue };
        let (row, col) = (i / sprite.w, i % sprite.w);
        let col = if flip_x { sprite.w - 1 - col } else { col };
        let quad = snapped(
            point(
                origin.x + px(col as f32 * scale),
                origin.y + px(row as f32 * scale),
            ),
            1.,
            1.,
            scale,
            sf,
        );
        window.paint_quad(fill(quad, to_hsla(c)));
    }
}

/// The bounds of `w` x `h` sprite pixels at `origin`, `scale` logical pixels each,
/// with every edge snapped to the device-pixel grid of `scale_factor`.
fn snapped(origin: Point<Pixels>, w: f32, h: f32, scale: f32, scale_factor: f32) -> Bounds<Pixels> {
    let x0 = snap(f32::from(origin.x), scale_factor);
    let y0 = snap(f32::from(origin.y), scale_factor);
    let x1 = snap(f32::from(origin.x) + w * scale, scale_factor);
    let y1 = snap(f32::from(origin.y) + h * scale, scale_factor);
    Bounds::new(point(px(x0), px(y0)), size(px(x1 - x0), px(y1 - y0)))
}

/// `v` logical pixels rounded to the nearest device pixel (`1 / scale_factor`).
fn snap(v: f32, scale_factor: f32) -> f32 {
    if scale_factor <= 0. {
        return v;
    }
    (v * scale_factor).round() / scale_factor
}

/// A palette RGBA colour as GPUI's colour type.
fn to_hsla(c: [u8; 4]) -> Hsla {
    Hsla::from(rgba(u32::from_be_bytes(c)))
}

/// The app logo ([`LOGO`]) as a `size_px` square, one quad per sprite pixel. Sizes that
/// are a multiple of 32 keep every sprite pixel the same width.
pub fn logo_element(size_px: f32) -> impl IntoElement {
    let scale = size_px / LOGO.w as f32;
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| paint_sprite(window, bounds.origin, scale, &LOGO, false),
    )
    .size(px(size_px))
    .flex_shrink_0()
}

#[cfg(test)]
mod tests {
    // Not `super::*`: GPUI's `test` attribute would shadow the standard one.
    use super::{DuckFsm, Duration, Progress, State, Thresholds, fast_forward, snap};

    #[test]
    fn snap_rounds_to_device_pixels() {
        assert_eq!(snap(10.3, 2.), 10.5);
        assert_eq!(snap(10.2, 2.), 10.);
        assert_eq!(snap(10.4, 1.), 10.);
        assert_eq!(snap(7.25, 0.), 7.25);
    }

    #[test]
    fn fast_forward_ends_the_scene() {
        let mut fsm = DuckFsm::new(Thresholds::default());
        let p = Progress {
            files: 10,
            ..Progress::default()
        };
        fsm.on_progress(&p, std::path::Path::new("/Users/me"));
        fsm.tick(Duration::from_secs(2));
        assert!(fsm.visible());
        fsm.on_finished();
        fast_forward(&mut fsm);
        assert_eq!(fsm.state, State::Done);
    }
}
