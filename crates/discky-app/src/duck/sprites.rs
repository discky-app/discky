//! Robo-duck pixel art: every sprite is a grid of palette characters.
//!
//! `'.'` is transparent; every other character is a key of [`PALETTE`], the
//! only place in the app with literal colours. Duck poses are 16x16, face
//! right (the renderer flips them when the duck walks left) and stand with
//! their feet on the bottom row, so frames can be swapped without offsets.

/// Sprite colours as RGBA, keyed by the character used in the sprite rows.
pub const PALETTE: &[(char, [u8; 4])] = &[
    ('k', [0x1e, 0x1e, 0x24, 0xff]), // outline
    ('y', [0xf2, 0xc1, 0x4e, 0xff]), // body
    ('Y', [0xff, 0xd9, 0x7a, 0xff]), // highlight
    ('o', [0xf0, 0x7e, 0x2f, 0xff]), // beak/feet
    ('g', [0x8a, 0x93, 0x9e, 0xff]), // metal
    ('G', [0xc5, 0xcc, 0xd4, 0xff]), // metal light
    ('c', [0x4f, 0xd1, 0xff, 0xff]), // eye LED
    ('p', [0xf4, 0xf1, 0xea, 0xff]), // paper
    ('b', [0xa9, 0x74, 0x42, 0xff]), // box
    ('B', [0x6e, 0x4a, 0x2b, 0xff]), // box dark
    ('r', [0xd9, 0x3b, 0x3b, 0xff]), // rope
    ('t', [0x3b, 0x4b, 0x5c, 0xff]), // bin
];

/// A pixel-art image: `h` rows of exactly `w` palette characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sprite {
    /// Width in pixels (characters per row).
    pub w: usize,
    /// Height in pixels (number of rows).
    pub h: usize,
    /// The rows, top to bottom; `'.'` is transparent.
    pub rows: &'static [&'static str],
}

/// What the duck is doing; selects an animation in [`frames`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pose {
    /// Standing still, blinking (2 frames).
    Idle,
    /// Walking empty-handed (4 frames).
    Walk,
    /// Walking with a paper stack held up over its back (4 frames).
    Carry,
    /// Walking with a rope over its shoulder, pulling a crate (4 frames).
    Drag,
    /// Tossing the papers into the bin (2 frames).
    Throw,
    /// Pushing the crate into the bin (3 frames).
    Shove,
    /// Standing still (1 frame).
    Stand,
}

/// The animation frames of `pose`, all 16x16 and facing right.
pub fn frames(pose: Pose) -> &'static [Sprite] {
    match pose {
        Pose::Idle => &IDLE,
        Pose::Walk => &WALK,
        Pose::Carry => &CARRY,
        Pose::Drag => &DRAG,
        Pose::Throw => &THROW,
        Pose::Shove => &SHOVE,
        Pose::Stand => &STAND,
    }
}

/// The RGBA colour of a sprite character; `None` for `'.'` and unknown keys.
pub fn color(ch: char) -> Option<[u8; 4]> {
    PALETTE
        .iter()
        .find(|(k, _)| *k == ch)
        .map(|(_, rgba)| *rgba)
}

/// `sprite` as RGBA pixels, each sprite pixel repeated `scale` x `scale` times:
/// `(w * scale) * (h * scale)` entries, row-major, `None` where transparent.
/// At scale 1 this is the colour grid the renderer paints one quad per entry from.
pub fn rasterize(sprite: &Sprite, scale: usize) -> Vec<Option<[u8; 4]>> {
    let w = sprite.w * scale;
    let mut out = Vec::with_capacity(w * sprite.h * scale);
    for row in sprite.rows {
        let line: Vec<Option<[u8; 4]>> = row
            .chars()
            .flat_map(|c| std::iter::repeat_n(color(c), scale))
            .collect();
        for _ in 0..scale {
            out.extend_from_slice(&line);
        }
    }
    out
}

/// Idle: eyes open, then a blink with a one-pixel bob.
static IDLE: [Sprite; 2] = [
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            "......kg..kg....",
            ".....ooo.ooo....",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "..........k.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykkk..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kgkg......",
            ".....oooooo.....",
        ],
    },
];

/// Walk cycle: stride, pass (bob), opposite stride, pass.
static WALK: [Sprite; 4] = [
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".....kg....kg...",
            "....kg......kg..",
            "...ooo......ooo.",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kgkg......",
            ".....oooooo.....",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            ".....kg....kg...",
            "....ooo....ooo..",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".......kg.kg....",
            "......ooo.oo....",
        ],
    },
];

/// Carry cycle: the raised hand is in columns 3..5 of the top row.
static CARRY: [Sprite; 4] = [
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "...GG.....c.....",
            "...kg.....k.....",
            "...kg...kkkkk...",
            "...kg..kyYYyyk..",
            "...kg..kyyykck..",
            "...kg..kyyyyykoo",
            "...kg..kyyyyykko",
            "kk.kg..kyyyyk...",
            "kykkgkkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".....kg....kg...",
            "....kg......kg..",
            "...ooo......ooo.",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "...GG.....c.....",
            "...kg.....k.....",
            "...kg...kkkkk...",
            "...kg..kyYYyyk..",
            "...kg..kyyykck..",
            "...kg..kyyyyykoo",
            "...kg..kyyyyykko",
            "kk.kg..kyyyyk...",
            "kykkgkkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kgkg......",
            ".....oooooo.....",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "...GG.....c.....",
            "...kg.....k.....",
            "...kg...kkkkk...",
            "...kg..kyYYyyk..",
            "...kg..kyyykck..",
            "...kg..kyyyyykoo",
            "...kg..kyyyyykko",
            "kk.kg..kyyyyk...",
            "kykkgkkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            ".....kg....kg...",
            "....ooo....ooo..",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "...GG.....c.....",
            "...kg.....k.....",
            "...kg...kkkkk...",
            "...kg..kyYYyyk..",
            "...kg..kyyykck..",
            "...kg..kyyyyykoo",
            "...kg..kyyyyykko",
            "kk.kg..kyyyyk...",
            "kykkgkkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".......kg.kg....",
            "......ooo.oo....",
        ],
    },
];

/// Drag cycle: the rope leaves the left edge on row 7 (row 8 when bobbing).
static DRAG: [Sprite; 4] = [
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "rrrrrGgkyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".....kg....kg...",
            "....kg......kg..",
            "...ooo......ooo.",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "rrrrrGgkyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kgkg......",
            ".....oooooo.....",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "rrrrrGgkyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            ".....kg....kg...",
            "....ooo....ooo..",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "................",
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "rrrrrGgkyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".......kg.kg....",
            "......ooo.oo....",
        ],
    },
];

/// Throw: arm up behind, then flung forward over the head.
static THROW: [Sprite; 2] = [
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "...GG.....c.....",
            "...kg.....k.....",
            "...kg...kkkkk...",
            "...kg..kyYYyyk..",
            "...kg..kyyykck..",
            "...kg..kyyyyykoo",
            "...kg..kyyyyykko",
            "kk.kg..kyyyyk...",
            "kykkgkkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            "......kg..kg....",
            ".....ooo.ooo....",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.kgGG",
            "..........kkgk..",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".....kg....kg...",
            "....kg......kg..",
            "...ooo......ooo.",
        ],
    },
];

/// Shove: the arm reaches further forward each frame.
static SHOVE: [Sprite; 3] = [
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGGk.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            "......kg..kg....",
            ".....ooo.ooo....",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGgG.",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            "......kg..kg....",
            ".....kg....kg...",
            "....ooo....ooo..",
        ],
    },
    Sprite {
        w: 16,
        h: 16,
        rows: &[
            "..........c.....",
            "..........k.....",
            "........kkkkk...",
            ".......kyYYyyk..",
            ".......kyyykck..",
            ".......kyyyyykoo",
            ".......kyyyyykko",
            "kk.....kyyyyk...",
            "kyk..kkyyyyyGk..",
            "kyykkyyyyyyGGgk.",
            "kyykYYYYkyyGGggG",
            ".kyykkkkyyygggk.",
            "..kkkkkkkkkkkk..",
            ".....kg....kg...",
            "....kg......kg..",
            "...ooo......ooo.",
        ],
    },
];

/// Stand: feet together, eye lit.
static STAND: [Sprite; 1] = [Sprite {
    w: 16,
    h: 16,
    rows: &[
        "..........c.....",
        "..........k.....",
        "........kkkkk...",
        ".......kyYYyyk..",
        ".......kyyykck..",
        ".......kyyyyykoo",
        ".......kyyyyykko",
        "kk.....kyyyyk...",
        "kyk..kkyyyyyGk..",
        "kyykkyyyyyyGGgk.",
        "kyykYYYYkyyGGgk.",
        ".kyykkkkyyygggk.",
        "..kkkkkkkkkkkk..",
        "......kg..kg....",
        "......kg..kg....",
        ".....ooo.ooo....",
    ],
}];

/// Paper stacks of 1, 2 and 3 sheets (8x3, 8x5, 8x7), drawn resting on the
/// raised hand in [`Pose::Carry`] (centred over columns 0..8, just above row 0).
pub const STACK: [Sprite; 3] = [
    Sprite {
        w: 8,
        h: 3,
        rows: &["kkkkkkkk", "kppppppk", "kkkkkkkk"],
    },
    Sprite {
        w: 8,
        h: 5,
        rows: &[".kkkkkkk", ".kpppppk", "kkkkkkkk", "kppppppk", "kkkkkkkk"],
    },
    Sprite {
        w: 8,
        h: 7,
        rows: &[
            "kkkkkkk.", "kpppppk.", ".kkkkkkk", ".kpppppk", "kkkkkkkk", "kppppppk", "kkkkkkkk",
        ],
    },
];

/// The 12x12 crate the duck drags on a rope for a big subtree.
pub const BLOCK: Sprite = Sprite {
    w: 12,
    h: 12,
    rows: &[
        "kkkkkkkkkkkk",
        "kbbbbbbbbbbk",
        "kBkkkkkkkkBk",
        "kbkbbbbbBkbk",
        "kbkbbbbBbkbk",
        "kbkbbbBbbkbk",
        "kbkbbBbbbkbk",
        "kbkbBbbbbkbk",
        "kbkBbbbbbkbk",
        "kBkkkkkkkkBk",
        "kbbbbbbbbbbk",
        "kkkkkkkkkkkk",
    ],
};

/// The 16x20 bin with its lid flipped open.
pub const BIN_OPEN: Sprite = Sprite {
    w: 16,
    h: 20,
    rows: &[
        "...kk...........",
        "..kggk..........",
        "..kGgk..........",
        "..kGgk..........",
        "..kGgkk.........",
        "..kGgggk........",
        "..kGgk..........",
        "..kGgk..........",
        "kkkkkkkkkkkkkkkk",
        "kGkkkkkkkkkkkkGk",
        ".kttttttttttttk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttttttttttttk.",
        "..kkkkkkkkkkkk..",
    ],
};

/// The 16x20 bin with its lid shut.
pub const BIN_CLOSED: Sprite = Sprite {
    w: 16,
    h: 20,
    rows: &[
        "................",
        "................",
        "................",
        "................",
        "......kkkk......",
        "......kggk......",
        "..kkkkkkkkkkkk..",
        ".kGGGGGGGGGGGGk.",
        "kkkkkkkkkkkkkkkk",
        "kGGGGGGGGGGGGGGk",
        ".kttttttttttttk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttGttGttGttGk.",
        ".kttttttttttttk.",
        "..kkkkkkkkkkkk..",
    ],
};

/// The 32x32 robo-duck head and shoulders: app icon and empty state.
pub const LOGO: Sprite = Sprite {
    w: 32,
    h: 32,
    rows: &[
        "..............cc................",
        ".............kcck...............",
        "..............kg................",
        "..............kg................",
        "..............kk................",
        "...........kkkyykkk.............",
        ".........kkyyyyyyyykk...........",
        "........kyYYYyyyyyyyyk..........",
        ".......kyYYYYYyyyyyyyyk.........",
        ".......kyYYYYYyyykkkyyk.........",
        "......kyyYYYYYyykpcckyyk........",
        "......kyyyYYYyyykccckyyk........",
        "......kyyyyyyyyykccckyyk........",
        ".....kyyyyyyyyyyykkkyyyyk.......",
        ".....kyyyyyyyyyyyyyyykkkkkkk....",
        "......kyyyyyyyyyyyyyykoooooook..",
        "......kyyyyGgyyyyyyyykooooooook.",
        "......kyyyyyyyyyyyyyykkkkkkkkk..",
        ".......kyyyyyyyyyyyyykoooooook..",
        ".......kyyyyyyyyyyyyykkkkkkkk...",
        "........kyyyyyyyyyyyyk..........",
        ".........kkyyyyyyyykk...........",
        "...........kkkyykkk.............",
        "..............kk................",
        ".........kkkkkkkkkkkk...........",
        ".......kkyyyyyyyyyyyykk.........",
        ".....kkyyykkkkkkkkkkyyykk.......",
        "....kyyyykgGGGGGGGGgkyyyyk......",
        "...kyyyyykggGgGgGgggkyyyyyk.....",
        "...kyyyyykggGgGgGgggkyyyyyk.....",
        "..kyyyyyykggGgGgGgggkyyyyyyk....",
        "..kyyyyyykggggggggggkyyyyyyk....",
    ],
};
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rasterize_walk_frame_at_scale_two() {
        let walk = &frames(Pose::Walk)[0];
        let px = rasterize(walk, 2);
        assert_eq!(px.len(), walk.w * 2 * walk.h * 2);
        let opaque = walk
            .rows
            .iter()
            .flat_map(|r| r.chars())
            .filter(|&c| color(c).is_some())
            .count();
        assert!(opaque > 0);
        assert_eq!(px.iter().filter(|p| p.is_some()).count(), 4 * opaque);
        // Row-major and scaled: the top-left 2x2 block is sprite pixel (0, 0).
        let w2 = walk.w * 2;
        let first = walk.rows[0].chars().next().and_then(color);
        assert_eq!(px[0], first);
        assert_eq!(px[1], first);
        assert_eq!(px[w2], first);
        assert_eq!(px[w2 + 1], first);
        // Sprite pixel (10, 0) is the antenna tip 'c'.
        assert_eq!(px[20], color('c'));
        assert_eq!(px[w2 + 21], color('c'));
    }

    fn all_sprites() -> Vec<(&'static str, &'static Sprite)> {
        let mut out = Vec::new();
        for pose in [
            Pose::Idle,
            Pose::Walk,
            Pose::Carry,
            Pose::Drag,
            Pose::Throw,
            Pose::Shove,
            Pose::Stand,
        ] {
            for s in frames(pose) {
                out.push(("pose", s));
            }
        }
        for s in &STACK {
            out.push(("stack", s));
        }
        out.push(("block", &BLOCK));
        out.push(("bin_open", &BIN_OPEN));
        out.push(("bin_closed", &BIN_CLOSED));
        out.push(("logo", &LOGO));
        out
    }

    #[test]
    fn all_frames_have_declared_size_and_known_chars() {
        for (name, s) in all_sprites() {
            assert_eq!(s.rows.len(), s.h, "{name}: row count");
            for row in s.rows {
                assert_eq!(row.chars().count(), s.w, "{name}: row {row:?}");
                for ch in row.chars() {
                    assert!(ch == '.' || color(ch).is_some(), "{name}: unknown {ch:?}");
                }
            }
        }
    }

    #[test]
    fn frame_counts_and_sizes_match_the_catalogue() {
        let expect = [
            (Pose::Idle, 2),
            (Pose::Walk, 4),
            (Pose::Carry, 4),
            (Pose::Drag, 4),
            (Pose::Throw, 2),
            (Pose::Shove, 3),
            (Pose::Stand, 1),
        ];
        for (pose, n) in expect {
            let f = frames(pose);
            assert_eq!(f.len(), n, "{pose:?}");
            for s in f {
                assert_eq!((s.w, s.h), (16, 16), "{pose:?}");
                assert!(
                    s.rows[15].chars().any(|c| c != '.'),
                    "{pose:?}: feet on the bottom row"
                );
            }
            for pair in f.windows(2) {
                assert_ne!(
                    pair[0].rows, pair[1].rows,
                    "{pose:?}: neighbouring frames must differ"
                );
            }
        }
        assert_eq!(STACK.map(|s| (s.w, s.h)), [(8, 3), (8, 5), (8, 7)]);
        assert_eq!((BLOCK.w, BLOCK.h), (12, 12));
        assert_eq!((BIN_OPEN.w, BIN_OPEN.h), (16, 20));
        assert_eq!((BIN_CLOSED.w, BIN_CLOSED.h), (16, 20));
        assert_eq!((LOGO.w, LOGO.h), (32, 32));
    }

    #[test]
    fn color_maps_palette_and_rejects_others() {
        assert_eq!(color('c'), Some([0x4f, 0xd1, 0xff, 0xff]));
        assert_eq!(color('.'), None);
        assert_eq!(color('z'), None);
    }
}
