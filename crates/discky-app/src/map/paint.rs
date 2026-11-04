//! Stateless painting of the disk map's tiles into a canvas.

use discky_core::rules::Category;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::*;

use super::model::{HEADER_H, LABEL_MIN_H, LABEL_MIN_W, Paint, Tile};
use crate::palette::{category_color, sequential};
use crate::sidebar::CATEGORIES;

/// Gap between a label and its tile's left edge, and the room kept on the right.
const LABEL_INSET: f32 = 4.0;
const ELLIPSIS: &str = "…";

/// The theme colours the map paints with, read once per render so the canvas closure
/// owns them.
#[derive(Clone, Copy)]
pub struct Colors {
    /// [`category_color`] of each of [`CATEGORIES`], in that order.
    categories: [Hsla; 7],
    pub background: Hsla,
    pub foreground: Hsla,
    pub muted: Hsla,
    pub muted_foreground: Hsla,
    danger: Hsla,
    accent: Hsla,
    chart_2: Hsla,
    warning: Hsla,
}

impl Colors {
    pub fn new(cx: &App) -> Self {
        let t = cx.theme();
        Colors {
            categories: CATEGORIES.map(|c| category_color(c, cx)),
            background: t.background,
            foreground: t.foreground,
            muted: t.muted,
            muted_foreground: t.muted_foreground,
            danger: t.danger,
            accent: t.accent,
            chart_2: t.chart_2,
            warning: t.warning,
        }
    }

    fn category(&self, c: Category) -> Hsla {
        CATEGORIES
            .iter()
            .position(|&k| k == c)
            .map_or(self.muted, |i| self.categories[i])
    }

    /// A tile's (or legend swatch's) fill.
    pub fn fill(&self, paint: Paint) -> Hsla {
        match paint {
            Paint::Category(Some(c)) => self.category(c),
            Paint::Category(None) => self.muted,
            Paint::Cloud => self.background,
            Paint::NoAccess => self.danger.opacity(0.35),
            Paint::Age(b) => sequential(self.accent, b),
            Paint::Files(b) => sequential(self.chart_2, b),
            Paint::Rest => self.muted.opacity(0.5),
        }
    }
}

/// Paints `tiles` (canvas-relative rects) into `bounds`, clipped to it, with a 2 px
/// outline on the `hover` tile.
pub fn paint_tiles(
    tiles: &[Tile],
    bounds: Bounds<Pixels>,
    hover: Option<usize>,
    colors: &Colors,
    window: &mut Window,
    cx: &mut App,
) {
    window.with_content_mask(Some(ContentMask { bounds }), |window| {
        let font = window.text_style().font();
        let font_size = rems(0.75).to_pixels(window.rem_size());
        for tile in tiles {
            let rect = tile_bounds(tile, bounds.origin);
            let (width, color, style) = if tile.paint == Paint::Cloud {
                (1., colors.muted_foreground, BorderStyle::Dashed)
            } else if tile.sparse {
                (2., colors.warning, BorderStyle::Solid)
            } else {
                (1., colors.background, BorderStyle::Solid)
            };
            window.paint_quad(quad(
                rect,
                px(0.),
                colors.fill(tile.paint),
                px(width),
                color,
                style,
            ));
            if tile.rect.w >= LABEL_MIN_W && tile.rect.h >= LABEL_MIN_H {
                paint_label(tile, rect, &font, font_size, colors.foreground, window, cx);
            }
        }
        if let Some(tile) = hover.and_then(|i| tiles.get(i)) {
            window.paint_quad(quad(
                tile_bounds(tile, bounds.origin),
                px(0.),
                transparent_black(),
                px(2.),
                colors.foreground,
                BorderStyle::Solid,
            ));
        }
    });
}

fn tile_bounds(tile: &Tile, origin: Point<Pixels>) -> Bounds<Pixels> {
    let r = tile.rect;
    Bounds::new(
        point(origin.x + px(r.x), origin.y + px(r.y)),
        size(px(r.w), px(r.h)),
    )
}

/// The tile's name (and caption) in its top-left corner, cut to fit with "…".
fn paint_label(
    tile: &Tile,
    rect: Bounds<Pixels>,
    font: &Font,
    font_size: Pixels,
    color: Hsla,
    window: &mut Window,
    cx: &mut App,
) {
    let text = match tile.caption {
        Some(c) => format!("{} · {c}", tile.label),
        None => tile.label.clone(),
    };
    let room = rect.size.width - px(2. * LABEL_INSET);
    let shape = |s: String, window: &mut Window| {
        let run = TextRun {
            len: s.len(),
            font: font.clone(),
            color,
            ..Default::default()
        };
        window
            .text_system()
            .shape_line(s.into(), font_size, &[run], None)
    };
    let mut line = shape(text.clone(), window);
    if line.width() > room {
        // Drop characters from the end, starting from a proportional guess.
        let chars: Vec<char> = text.chars().collect();
        let ratio = f32::from(room) / f32::from(line.width());
        let mut keep = ((chars.len() as f32) * ratio).floor() as usize;
        loop {
            let cut: String = chars[..keep.min(chars.len())].iter().collect();
            line = shape(format!("{}{ELLIPSIS}", cut.trim_end()), window);
            if line.width() <= room || keep == 0 {
                break;
            }
            keep -= 1;
        }
        if line.width() > room {
            return;
        }
    }
    let origin = point(rect.origin.x + px(LABEL_INSET), rect.origin.y);
    let line_height = px(HEADER_H.min(tile.rect.h));
    let _ = line.paint(origin, line_height, TextAlign::Left, None, window, cx);
}
