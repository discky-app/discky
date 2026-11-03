//! `cargo xtask icon`: the app icon and README logo, rendered from the pixel [`LOGO`].

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::process::Command;

use discky_app::duck::sprites::{LOGO, Sprite, rasterize};

/// The iconset entries: file name and pixel size. The 16 px image is the 32 px one
/// halved by [`downscale_half`] (the 32x32 sprite cannot be upscaled to 16).
const ICONSET: &[(&str, usize)] = &[
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
];

/// Write the iconset to `target/AppIcon.iconset`, pack it into `assets/AppIcon.icns`
/// with `iconutil`, and write `assets/logo.png` at 512 px.
pub fn run(root: &Path) -> Result<(), String> {
    let iconset = crate::target_dir(root).join("AppIcon.iconset");
    if iconset.exists() {
        std::fs::remove_dir_all(&iconset)
            .map_err(|e| format!("cannot clear {}: {e}", iconset.display()))?;
    }
    std::fs::create_dir_all(&iconset)
        .map_err(|e| format!("cannot create {}: {e}", iconset.display()))?;
    let assets = root.join("assets");
    std::fs::create_dir_all(&assets)
        .map_err(|e| format!("cannot create {}: {e}", assets.display()))?;

    for &(name, size) in ICONSET {
        write_png(&iconset.join(name), size, &render(&LOGO, size))?;
    }
    let icns = assets.join("AppIcon.icns");
    crate::run_capture(
        Command::new("iconutil")
            .arg("-c")
            .arg("icns")
            .arg("-o")
            .arg(&icns)
            .arg(&iconset),
    )?;
    let logo = assets.join("logo.png");
    write_png(&logo, 512, &render(&LOGO, 512))?;
    println!("wrote {}", icns.display());
    println!("wrote {}", logo.display());
    Ok(())
}

/// `sprite` (square, `sprite.w` px) as a `size` px square of RGBA bytes: upscaled by
/// `size / sprite.w`, or the 2x image halved when `size` is half the sprite.
fn render(sprite: &Sprite, size: usize) -> Vec<u8> {
    if size * 2 == sprite.w {
        downscale_half(&upscale(sprite, 1), sprite.w)
    } else {
        upscale(sprite, size / sprite.w)
    }
}

/// `sprite` upscaled by `factor` with nearest neighbour: RGBA bytes, row-major,
/// transparent pixels as `[0, 0, 0, 0]`.
pub fn upscale(sprite: &Sprite, factor: usize) -> Vec<u8> {
    rasterize(sprite, factor)
        .into_iter()
        .flat_map(|px| px.unwrap_or([0; 4]))
        .collect()
}

/// A `side` x `side` RGBA image halved: each 2x2 block becomes its most frequent opaque
/// colour (the first one on a tie), or transparent when 3 or 4 of its pixels are.
pub fn downscale_half(rgba: &[u8], side: usize) -> Vec<u8> {
    let half = side / 2;
    let px = |x: usize, y: usize| -> [u8; 4] {
        let i = (y * side + x) * 4;
        [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
    };
    let mut out = Vec::with_capacity(half * half * 4);
    for y in 0..half {
        for x in 0..half {
            let block = [
                px(2 * x, 2 * y),
                px(2 * x + 1, 2 * y),
                px(2 * x, 2 * y + 1),
                px(2 * x + 1, 2 * y + 1),
            ];
            let opaque: Vec<[u8; 4]> = block.into_iter().filter(|p| p[3] != 0).collect();
            let pick = if opaque.len() <= 1 {
                [0; 4]
            } else {
                let count = |c: &[u8; 4]| opaque.iter().filter(|p| *p == c).count();
                // `max_by_key` keeps the last maximum; scan reversed to keep the first.
                opaque
                    .iter()
                    .rev()
                    .max_by_key(|c| count(c))
                    .copied()
                    .unwrap_or([0; 4])
            };
            out.extend_from_slice(&pick);
        }
    }
    out
}

/// Write a `size` x `size` RGBA8 PNG.
fn write_png(path: &Path, size: usize, rgba: &[u8]) -> Result<(), String> {
    let err = |e: &dyn std::fmt::Display| format!("cannot write {}: {e}", path.display());
    let side = u32::try_from(size).map_err(|e| err(&e))?;
    let file = File::create(path).map_err(|e| err(&e))?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), side, side);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|e| err(&e))?;
    writer.write_image_data(rgba).map_err(|e| err(&e))?;
    writer.finish().map_err(|e| err(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use discky_app::duck::sprites::color;

    #[test]
    fn upscale_nearest_keeps_pixels() {
        let sprite = Sprite {
            w: 2,
            h: 2,
            rows: &["ky", ".o"],
        };
        let px = upscale(&sprite, 3);
        assert_eq!(px.len(), 6 * 6 * 4);
        let (k, y, o) = (
            color('k').unwrap(),
            color('y').unwrap(),
            color('o').unwrap(),
        );
        for row in 0..6 {
            for col in 0..6 {
                let i = (row * 6 + col) * 4;
                let want = match (row / 3, col / 3) {
                    (0, 0) => k,
                    (0, 1) => y,
                    (1, 0) => [0, 0, 0, 0],
                    _ => o,
                };
                assert_eq!(px[i..i + 4], want, "pixel ({row}, {col})");
            }
        }
    }

    #[test]
    fn downscale_half_takes_majority_and_drops_mostly_transparent() {
        let (a, b, t) = ([1, 2, 3, 255], [9, 9, 9, 255], [0u8; 4]);
        // 4x4: block (0,0) = a a / a b -> a; block (1,0) = t t / t b -> transparent;
        // block (0,1) = t a / b t -> a (tie, first); block (1,1) = t t / t t -> transparent.
        let rows: [[[u8; 4]; 4]; 4] = [[a, a, t, t], [a, b, t, b], [t, a, t, t], [b, t, t, t]];
        let rgba: Vec<u8> = rows.iter().flatten().flatten().copied().collect();
        let half = downscale_half(&rgba, 4);
        assert_eq!(half, [a, t, a, t].concat());
    }

    #[test]
    fn every_iconset_size_renders_square() {
        for &(name, size) in ICONSET {
            assert_eq!(render(&LOGO, size).len(), size * size * 4, "{name}");
        }
    }
}
