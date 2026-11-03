//! Squarified treemap layout (Bruls, Huizing, van Wijk 2000). Pure: no GPUI.

/// Axis-aligned rectangle in pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Rect {
    pub fn contains(&self, x: f32, y: f32) -> bool {
        x >= self.x && x < self.x + self.w && y >= self.y && y < self.y + self.h
    }

    pub fn area(&self) -> f32 {
        self.w * self.h
    }

    /// Shrinks every side by `by`; the size never goes negative.
    pub fn inset(&self, by: f32) -> Rect {
        let w = (self.w - 2.0 * by).max(0.0);
        let h = (self.h - 2.0 * by).max(0.0);
        Rect {
            x: self.x + (self.w - w) / 2.0,
            y: self.y + (self.h - h) / 2.0,
            w,
            h,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Item<K: Copy> {
    pub key: K,
    pub weight: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Slot<K: Copy> {
    Item(K),
    Rest { count: usize, weight: u64 },
}

#[derive(Debug, Clone, Copy)]
pub struct Placed<K: Copy> {
    pub slot: Slot<K>,
    pub rect: Rect,
}

pub const MIN_TILE_PX: f32 = 3.0;
pub const MAX_CHILDREN: usize = 400;

/// Squarified treemap (Bruls, Huizing, van Wijk). Items sorted by weight desc (stable);
/// zero weights dropped; after the first `MAX_CHILDREN` items, or once an item's tile would
/// have a side < `MIN_TILE_PX`, the remaining items become one `Rest` slot laid out with
/// their combined weight. Rects tile `rect` exactly (areas ∝ weights).
///
/// Pixel floor rule: an item's side estimate is its area share of `rect` divided by the longer
/// side of `rect`; the first item whose estimate is below `MIN_TILE_PX` starts the tail. Since
/// items are sorted descending, the tail is a suffix. The largest item is never merged, and a
/// tail of exactly one item stays a plain `Item`.
pub fn squarify<K: Copy>(items: &[Item<K>], rect: Rect) -> Vec<Placed<K>> {
    if !(rect.w > 0.0 && rect.h > 0.0) {
        return Vec::new();
    }
    let mut sorted: Vec<Item<K>> = items.iter().copied().filter(|i| i.weight > 0).collect();
    sorted.sort_by_key(|i| std::cmp::Reverse(i.weight));
    if sorted.is_empty() {
        return Vec::new();
    }

    let total: f64 = sorted.iter().map(|i| i.weight as f64).sum();
    let rect_area = f64::from(rect.w) * f64::from(rect.h);
    let longer = f64::from(rect.w.max(rect.h));
    let floor = f64::from(MIN_TILE_PX);

    let mut keep = sorted.len().min(MAX_CHILDREN);
    for (i, item) in sorted.iter().enumerate().take(keep).skip(1) {
        if item.weight as f64 / total * rect_area / longer < floor {
            keep = i;
            break;
        }
    }
    if sorted.len() - keep == 1 {
        keep += 1;
    }

    let mut slots: Vec<(Slot<K>, f64)> = sorted[..keep]
        .iter()
        .map(|i| (Slot::Item(i.key), i.weight as f64))
        .collect();
    if keep < sorted.len() {
        let tail = &sorted[keep..];
        let weight: u64 = tail.iter().map(|i| i.weight).sum();
        slots.push((
            Slot::Rest {
                count: tail.len(),
                weight,
            },
            weight as f64,
        ));
    }

    let scale = rect_area / total;
    let areas: Vec<f64> = slots.iter().map(|(_, w)| w * scale).collect();
    let mut out = Vec::with_capacity(slots.len());
    lay_out(&slots, &areas, rect, &mut out);
    out
}

/// Worst aspect ratio of a row with area sum `sum`, extremes `max`/`min`, on a side of length `side`.
fn worst(sum: f64, max: f64, min: f64, side: f64) -> f64 {
    let s2 = side * side;
    let sum2 = sum * sum;
    (s2 * max / sum2).max(sum2 / (s2 * min))
}

fn lay_out<K: Copy>(slots: &[(Slot<K>, f64)], areas: &[f64], rect: Rect, out: &mut Vec<Placed<K>>) {
    let (mut x, mut y) = (f64::from(rect.x), f64::from(rect.y));
    let (mut w, mut h) = (f64::from(rect.w), f64::from(rect.h));
    let mut start = 0;
    while start < areas.len() {
        let horizontal = w >= h; // row is a column on the left, stacked top to bottom
        let side = if horizontal { h } else { w };

        let mut end = start + 1;
        let mut sum = areas[start];
        let (mut max, mut min) = (areas[start], areas[start]);
        let mut current = worst(sum, max, min, side);
        while end < areas.len() {
            let a = areas[end];
            let next = worst(sum + a, max.max(a), min.min(a), side);
            if next > current {
                break;
            }
            sum += a;
            max = max.max(a);
            min = min.min(a);
            current = next;
            end += 1;
        }

        let last_row = end == areas.len();
        let thickness = if last_row {
            if horizontal { w } else { h }
        } else {
            sum / side
        };
        let mut offset = 0.0;
        for i in start..end {
            let len = if i + 1 == end {
                side - offset
            } else {
                areas[i] / thickness
            };
            let r = if horizontal {
                Rect {
                    x: x as f32,
                    y: (y + offset) as f32,
                    w: thickness as f32,
                    h: len as f32,
                }
            } else {
                Rect {
                    x: (x + offset) as f32,
                    y: y as f32,
                    w: len as f32,
                    h: thickness as f32,
                }
            };
            out.push(Placed {
                slot: slots[i].0,
                rect: r,
            });
            offset += len;
        }

        if horizontal {
            x += thickness;
            w -= thickness;
        } else {
            y += thickness;
            h -= thickness;
        }
        start = end;
    }
}

#[cfg(test)]
mod tests {
    use super::{Item, MAX_CHILDREN, Placed, Rect, Slot, squarify};

    fn items(ws: &[u64]) -> Vec<Item<usize>> {
        ws.iter()
            .enumerate()
            .map(|(key, &weight)| Item { key, weight })
            .collect()
    }

    fn overlap(a: &Rect, b: &Rect) -> f64 {
        let dx =
            (f64::from(a.x + a.w).min(f64::from(b.x + b.w)) - f64::from(a.x.max(b.x))).max(0.0);
        let dy =
            (f64::from(a.y + a.h).min(f64::from(b.y + b.h)) - f64::from(a.y.max(b.y))).max(0.0);
        dx * dy
    }

    fn total_area(p: &[Placed<usize>]) -> f64 {
        p.iter()
            .map(|p| f64::from(p.rect.w) * f64::from(p.rect.h))
            .sum()
    }

    #[test]
    fn bruls_example_first_row() {
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            w: 600.0,
            h: 400.0,
        };
        let placed = squarify(&items(&[6, 6, 4, 3, 2, 2, 1]), rect);
        assert_eq!(placed.len(), 7);
        for p in &placed[..2] {
            assert_eq!(p.rect.x, 0.0);
            assert!((p.rect.w - 300.0).abs() < 1e-3, "{:?}", p.rect);
            assert!((p.rect.h - 200.0).abs() < 1e-3, "{:?}", p.rect);
        }
        assert_eq!(placed[0].rect.y, 0.0);
        assert!((placed[1].rect.y - 200.0).abs() < 1e-3);
    }

    #[test]
    fn areas_are_proportional_and_tile_the_rect() {
        let ws: Vec<u64> = (1..=40u64).map(|i| (i * 7919) % 97 + 50).collect();
        let rect = Rect {
            x: 10.0,
            y: 20.0,
            w: 600.0,
            h: 400.0,
        };
        let placed = squarify(&items(&ws), rect);
        assert_eq!(placed.len(), ws.len());
        let total = total_area(&placed);
        assert!((total - 600.0 * 400.0).abs() < 0.01, "total {total}");
        let sum_w: u64 = ws.iter().sum();
        for p in &placed {
            let Slot::Item(k) = p.slot else {
                panic!("unexpected Rest")
            };
            let share = f64::from(p.rect.w) * f64::from(p.rect.h) / total;
            assert!((share - ws[k] as f64 / sum_w as f64).abs() < 1e-3);
            assert!(p.rect.x >= rect.x - 1e-3 && p.rect.x + p.rect.w <= rect.x + rect.w + 1e-3);
            assert!(p.rect.y >= rect.y - 1e-3 && p.rect.y + p.rect.h <= rect.y + rect.h + 1e-3);
        }
        for (i, a) in placed.iter().enumerate() {
            for b in &placed[i + 1..] {
                assert!(overlap(&a.rect, &b.rect) < 0.05);
            }
        }
    }

    #[test]
    fn zero_weights_are_dropped() {
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            w: 100.0,
            h: 100.0,
        };
        assert_eq!(squarify(&items(&[5, 0, 3]), rect).len(), 2);
    }

    #[test]
    fn tail_is_merged_into_rest_preserving_area() {
        let mut ws = vec![10_000u64];
        ws.extend(std::iter::repeat_n(1, 2_000));
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            w: 200.0,
            h: 100.0,
        };
        let placed = squarify(&items(&ws), rect);
        assert!(placed.len() <= MAX_CHILDREN + 1);
        let rests: Vec<_> = placed
            .iter()
            .filter_map(|p| match p.slot {
                Slot::Rest { count, weight } => Some((count, weight)),
                Slot::Item(_) => None,
            })
            .collect();
        assert_eq!(rests.len(), 1);
        let n_items = placed.len() - 1;
        assert_eq!(rests[0].0 + n_items, 2_001);
        assert_eq!(rests[0].1, rests[0].0 as u64);
        assert!((total_area(&placed) - 20_000.0).abs() < 0.5);
    }

    #[test]
    fn max_children_caps_items_even_when_tiles_are_big() {
        let ws = vec![1u64; 500];
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            w: 4000.0,
            h: 4000.0,
        };
        let placed = squarify(&items(&ws), rect);
        assert_eq!(placed.len(), MAX_CHILDREN + 1);
        assert_eq!(
            placed.last().map(|p| p.slot),
            Some(Slot::Rest {
                count: 100,
                weight: 100
            })
        );
    }

    #[test]
    fn tiny_tiles_are_merged_by_pixel_floor() {
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            w: 100.0,
            h: 100.0,
        };
        let placed = squarify(&items(&[1000, 1, 1, 1]), rect);
        assert_eq!(placed.len(), 2);
        assert_eq!(placed[0].slot, Slot::Item(0));
        assert_eq!(
            placed[1].slot,
            Slot::Rest {
                count: 3,
                weight: 3
            }
        );
        assert!((total_area(&placed) - 10_000.0).abs() < 0.01);
    }

    #[test]
    fn degenerate_rect_yields_nothing() {
        let it = items(&[1, 2]);
        assert!(
            squarify(
                &it,
                Rect {
                    x: 0.0,
                    y: 0.0,
                    w: 0.0,
                    h: 10.0
                }
            )
            .is_empty()
        );
        assert!(
            squarify(
                &it,
                Rect {
                    x: 0.0,
                    y: 0.0,
                    w: 10.0,
                    h: -1.0
                }
            )
            .is_empty()
        );
    }
}
