//! The Overview screen's view model, built from the engine without any GPUI types.

use std::path::Path;

use discky_core::Engine;
use discky_core::findings::Finding;
use discky_core::index::snapshot::Actor;
use discky_core::query::{self, Overview};
use discky_core::rules::Category;

use crate::format;
use crate::sidebar::CATEGORIES;

/// How many findings each category card lists.
pub const CARD_ROWS: usize = 4;

/// Age in seconds after which the toolbar suggests a rescan (24 h).
pub const STALE_AFTER: i64 = 24 * 60 * 60;

/// Everything the Overview screen shows.
#[derive(Clone, Debug)]
pub struct OverviewModel {
    /// "Macintosh HD · 242 GB of 460 GB used".
    pub volume_line: String,
    /// "scanned 23 s ago by Discky.app" / "… by discky-mcp"; `None` without a snapshot.
    pub scanned_line: Option<String>,
    /// "Data from <when>" when the snapshot is older than [`STALE_AFTER`] seconds.
    pub stale_line: Option<String>,
    /// Bytes that can be freed safely (findings that regenerate on their own).
    pub safe_to_free: u64,
    /// How exact `safe_to_free` is; empty when unknown.
    pub exact_note: &'static str,
    /// The seven categories (nonzero only), then "Other scanned" and "Free"; fractions of
    /// the volume's total size.
    pub bar: Vec<BarSegment>,
    /// Categories with at least one finding, in sidebar order.
    pub cards: Vec<CategoryCard>,
    /// Folders the last scan could not read.
    pub no_access: usize,
    /// The engine's last background error, shown as a warning banner.
    pub last_error: Option<String>,
}

/// One segment of the disk bar.
#[derive(Clone, Debug, PartialEq)]
pub struct BarSegment {
    pub label: String,
    pub bytes: u64,
    /// Share of the volume's total size, `0.0..=1.0`.
    pub fraction: f32,
    /// The category this segment stands for; `None` for "Other scanned" and "Free".
    pub category: Option<Category>,
}

/// A category card: its weight, how many findings it has, and the largest few.
#[derive(Clone, Debug)]
pub struct CategoryCard {
    pub category: Category,
    /// `allocated` bytes of the category (`Overview::by_category`).
    pub total: u64,
    /// Number of findings in the category; for Applications the number of apps not opened
    /// in 6 months (see [`unused_apps_page`]).
    pub count: usize,
    /// The first [`CARD_ROWS`] findings (largest first); for Applications the largest
    /// unused apps.
    pub top: Vec<Finding>,
    /// Findings not listed in `top`.
    pub more: usize,
}

/// Build the model from `engine`'s current snapshot; `now` is Unix seconds.
pub fn build(engine: &Engine, now: i64) -> OverviewModel {
    // One snapshot for both the totals and the cards, so a scan finishing meanwhile cannot
    // mix two snapshots.
    let snap = engine.snapshot();
    let overview = query::disk_overview(snap.as_deref());
    let pages = |c: Category| match snap.as_deref() {
        Some(s) if c == Category::Apps => {
            let (apps, _) = query::findings_in(s, Some(c), None, 0, None, 0, usize::MAX);
            unused_apps_page(apps, now)
        }
        Some(s) => {
            let (page, total) = query::findings_in(s, Some(c), None, 0, None, 0, CARD_ROWS);
            (page.into_iter().cloned().collect(), total)
        }
        None => (Vec::new(), 0),
    };
    build_from(&overview, pages, engine.last_error(), now)
}

/// The Applications card's page: the [`CARD_ROWS`] largest of `findings` that are apps not
/// opened in 6 months at `now` (`query::is_unused_app`), and how many such apps there are.
pub fn unused_apps_page<'a>(
    findings: impl IntoIterator<Item = &'a Finding>,
    now: i64,
) -> (Vec<Finding>, usize) {
    let mut unused: Vec<&Finding> = findings
        .into_iter()
        .filter(|f| query::is_unused_app(f, now))
        .collect();
    unused.sort_by_key(|f| std::cmp::Reverse(f.allocated));
    let total = unused.len();
    (unused.into_iter().take(CARD_ROWS).cloned().collect(), total)
}

/// A card's header: "Applications · 19 not opened in 6 months", otherwise
/// "Dev caches · 9.1 GB · 12 items".
pub fn card_header(card: &CategoryCard) -> String {
    if card.category == Category::Apps {
        return format!("{} · {} not opened in 6 months", card.category, card.count);
    }
    format!(
        "{} · {} · {} {}",
        card.category,
        format::bytes(card.total),
        card.count,
        if card.count == 1 { "item" } else { "items" }
    )
}

/// Build the model from an `overview`, a page source returning the first [`CARD_ROWS`]
/// findings of a category with the category's total count, and the engine's last error.
pub fn build_from(
    overview: &Overview,
    pages: impl Fn(Category) -> (Vec<Finding>, usize),
    last_error: Option<String>,
    now: i64,
) -> OverviewModel {
    let v = &overview.volume;
    let volume_line = format!(
        "{} · {} of {} used",
        volume_name(&v.mount),
        format::bytes(v.used),
        format::bytes(v.total)
    );
    let scanned_line = overview.snapshot_at.zip(overview.actor).map(|(at, actor)| {
        format!(
            "scanned {} by {}",
            format::relative(at, now),
            actor_name(actor)
        )
    });
    let stale_line = overview
        .snapshot_at
        .filter(|&at| now - at > STALE_AFTER)
        .map(|at| format!("Data from {}", format::when(at)));
    let exact_note = match overview.exact_private_size {
        Some(true) => "Frees is exact (local snapshots considered)",
        Some(false) => "Frees ignores blocks held by local snapshots",
        None => "",
    };
    let weight = |c: Category| {
        overview
            .by_category
            .iter()
            .find(|(k, _)| *k == c)
            .map_or(0, |(_, b)| *b)
    };
    let cards = CATEGORIES
        .iter()
        .filter_map(|&category| {
            let (top, count) = pages(category);
            (count > 0).then(|| CategoryCard {
                category,
                total: weight(category),
                count,
                more: count.saturating_sub(top.len()),
                top,
            })
        })
        .collect();
    OverviewModel {
        volume_line,
        scanned_line,
        stale_line,
        safe_to_free: overview.safe_to_free,
        exact_note,
        bar: bar(overview, weight),
        cards,
        no_access: overview.no_access,
        last_error,
    }
}

/// The disk bar: nonzero categories, "Other scanned", "Free". The used part (categories
/// and other) is capped at what is not free, and everything at the volume's size, so the
/// fractions never add up to more than 1.
fn bar(overview: &Overview, weight: impl Fn(Category) -> u64) -> Vec<BarSegment> {
    let total = overview.volume.total;
    let free = overview.volume.available.min(total);
    let mut room = total - free;
    let fraction = |bytes: u64| {
        if total == 0 {
            0.0
        } else {
            (bytes as f64 / total as f64) as f32
        }
    };
    let mut take = |bytes: u64| {
        let shown = bytes.min(room);
        room -= shown;
        fraction(shown)
    };
    let mut segments = Vec::new();
    let mut in_categories = 0u64;
    for &c in &CATEGORIES {
        let bytes = weight(c);
        if bytes == 0 {
            continue;
        }
        in_categories = in_categories.saturating_add(bytes);
        segments.push(BarSegment {
            label: c.to_string(),
            bytes,
            fraction: take(bytes),
            category: Some(c),
        });
    }
    let other = overview.scanned_allocated.saturating_sub(in_categories);
    segments.push(BarSegment {
        label: "Other scanned".to_string(),
        bytes: other,
        fraction: take(other),
        category: None,
    });
    segments.push(BarSegment {
        label: "Free".to_string(),
        bytes: overview.volume.available,
        fraction: fraction(free),
        category: None,
    });
    segments
}

/// Who made the snapshot, as the user knows it.
fn actor_name(actor: Actor) -> &'static str {
    match actor {
        Actor::App => "Discky.app",
        Actor::Mcp => "discky-mcp",
    }
}

/// The volume's name: the startup disk's name (as listed in `/Volumes`) for the root and
/// data volumes, the mount point's last component otherwise.
fn volume_name(mount: &Path) -> String {
    if mount == Path::new("/") || mount == Path::new("/System/Volumes/Data") {
        return startup_disk_name();
    }
    mount.file_name().map_or_else(
        || mount.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// The `/Volumes` entry that links to `/` (the startup disk's name), or "Macintosh HD".
fn startup_disk_name() -> String {
    std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .find(|e| std::fs::read_link(e.path()).is_ok_and(|t| t == Path::new("/")))
        .map_or_else(
            || "Macintosh HD".to_string(),
            |e| e.file_name().to_string_lossy().into_owned(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use discky_core::findings::{FindingId, Removal};
    use discky_core::query::VolumeInfo;
    use discky_core::rules::SafetyLabel;
    use discky_core::{DisckyPaths, EngineOptions};
    use std::path::PathBuf;

    const GB: u64 = 1_000_000_000;

    fn finding(i: usize, category: Category, allocated: u64) -> Finding {
        Finding {
            id: FindingId(format!("f{i}")),
            category,
            title: format!("Finding {i}"),
            subtitle: None,
            path: None,
            node: None,
            allocated,
            logical: allocated,
            freed_if_deleted: allocated,
            modified: None,
            label: SafetyLabel::Regenerates,
            rule_id: "test".into(),
            explain: String::new(),
            removal: Removal::Trash { paths: vec![] },
            flags: vec![],
            components: Vec::new(),
        }
    }

    fn overview(by_category: Vec<(Category, u64)>, scanned: u64) -> Overview {
        Overview {
            volume: VolumeInfo {
                mount: PathBuf::from("/Volumes/Data"),
                total: 100 * GB,
                used: 60 * GB,
                available: 40 * GB,
            },
            snapshot_at: Some(1_000),
            actor: Some(Actor::Mcp),
            scanned_allocated: scanned,
            by_category,
            protected_bytes: 0,
            safe_to_free: 5 * GB,
            no_access: 3,
            apps_unused: 0,
            exact_private_size: Some(false),
        }
    }

    #[test]
    fn overview_model_without_snapshot() {
        let dir = std::env::temp_dir().join(format!("discky-app-{}-overview", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let engine = Engine::open_with(EngineOptions {
            paths: DisckyPaths {
                config: dir.join("config.toml"),
                snapshot: dir.join("snapshot.bin"),
                log: dir.join("removals.log"),
            },
            actor: Actor::App,
            trash_bin: PathBuf::from("/usr/bin/false"),
        })
        .unwrap();
        let m = build(&engine, 1_000);
        assert_eq!(m.scanned_line, None);
        assert!(m.cards.is_empty());
        let labels: Vec<&str> = m.bar.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["Other scanned", "Free"]);
        assert_eq!(m.safe_to_free, 0);
        assert_eq!(m.exact_note, "");
        assert_eq!(m.no_access, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cards_take_top_four_and_count_more() {
        let findings: Vec<Finding> = (0..6)
            .map(|i| finding(i, Category::AppCaches, (10 - i as u64) * GB))
            .collect();
        let total: u64 = findings.iter().map(|f| f.allocated).sum();
        let ov = overview(
            CATEGORIES
                .iter()
                .map(|&c| (c, if c == Category::AppCaches { total } else { 0 }))
                .collect(),
            total,
        );
        let pages = |c: Category| {
            let all: Vec<Finding> = findings
                .iter()
                .filter(|f| f.category == c)
                .cloned()
                .collect();
            let n = all.len();
            (all.into_iter().take(CARD_ROWS).collect(), n)
        };
        let m = build_from(&ov, pages, None, 1_023);
        assert_eq!(m.cards.len(), 1);
        let card = &m.cards[0];
        assert_eq!(card.category, Category::AppCaches);
        assert_eq!(card.top.len(), 4);
        assert_eq!(card.more, 2);
        assert_eq!(card.count, 6);
        assert_eq!(card.total, total);
        assert_eq!(card.top[0].title, "Finding 0");
        assert_eq!(
            m.scanned_line.as_deref(),
            Some("scanned 23 s ago by discky-mcp")
        );
        assert_eq!(m.volume_line, "Data · 60 GB of 100 GB used");
        assert_eq!(m.exact_note, "Frees ignores blocks held by local snapshots");
        assert_eq!(m.no_access, 3);
    }

    #[test]
    fn apps_card_lists_the_largest_unused_apps() {
        let day = 86_400;
        let now = 1_000 * day;
        let mut findings: Vec<Finding> = (0..7)
            .map(|i| finding(i, Category::Apps, (i as u64 + 1) * GB))
            .collect();
        for f in &mut findings {
            f.rule_id = "apps".into();
        }
        // The largest app was opened yesterday; a leftover group is not an app.
        findings[6].modified = Some(now - day);
        findings[5].rule_id = "app-leftovers".into();
        let (top, count) = unused_apps_page(&findings, now);
        assert_eq!(count, 5);
        let titles: Vec<&str> = top.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["Finding 4", "Finding 3", "Finding 2", "Finding 1"]);
        let card = CategoryCard {
            category: Category::Apps,
            total: 28 * GB,
            count,
            more: count - top.len(),
            top,
        };
        assert_eq!(
            card_header(&card),
            "Applications · 5 not opened in 6 months"
        );
        assert_eq!(card.more, 1);
        let card = CategoryCard {
            category: Category::DevCaches,
            count: 1,
            ..card
        };
        assert_eq!(card_header(&card), "Dev caches · 28 GB · 1 item");
    }

    #[test]
    fn no_access_is_kept_alongside_cards() {
        let mut ov = overview(vec![(Category::Models, 2 * GB)], 10 * GB);
        ov.no_access = 7;
        let pages = |c: Category| {
            if c == Category::Models {
                (vec![finding(0, c, 2 * GB)], 1)
            } else {
                (Vec::new(), 0)
            }
        };
        let m = build_from(&ov, pages, None, 1_000);
        assert_eq!(m.no_access, 7);
        assert!(m.scanned_line.is_some());
        assert_eq!(m.cards.len(), 1);
        assert_eq!(m.cards[0].more, 0);
    }

    #[test]
    fn stale_line_only_after_a_day() {
        let ov = overview(vec![(Category::Models, GB)], 10 * GB);
        let none = |_| (Vec::new(), 0);
        assert_eq!(
            build_from(&ov, none, None, 1_000 + STALE_AFTER).stale_line,
            None
        );
        let stale = build_from(&ov, none, None, 1_001 + STALE_AFTER).stale_line;
        assert!(stale.is_some_and(|s| s.starts_with("Data from ")));
    }

    #[test]
    fn bar_fractions_sum_to_one_or_less() {
        // Category totals larger than the scan, and a scan larger than the disk: the bar
        // still never overflows.
        let ov = overview(
            vec![
                (Category::Apps, 30 * GB),
                (Category::AppCaches, 0),
                (Category::DevCaches, 50 * GB),
                (Category::LargeOld, 40 * GB),
            ],
            200 * GB,
        );
        let m = build_from(&ov, |_| (Vec::new(), 0), Some("boom".into()), 0);
        let sum: f32 = m.bar.iter().map(|s| s.fraction).sum();
        assert!(sum <= 1.0 + 1e-6, "sum = {sum}");
        assert!(m.bar.iter().all(|s| s.fraction >= 0.0));
        let labels: Vec<&str> = m.bar.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Applications",
                "Dev caches",
                "Large & old",
                "Other scanned",
                "Free"
            ]
        );
        assert_eq!(m.last_error.as_deref(), Some("boom"));

        // A typical case adds up to the used share plus free.
        let ov = overview(vec![(Category::Apps, 10 * GB)], 50 * GB);
        let m = build_from(&ov, |_| (Vec::new(), 0), None, 0);
        let fractions: Vec<f32> = m.bar.iter().map(|s| s.fraction).collect();
        assert_eq!(fractions, [0.1, 0.4, 0.4]);

        // An unknown disk size gives empty fractions, not NaN.
        let mut ov = overview(vec![(Category::Apps, 10 * GB)], 50 * GB);
        ov.volume.total = 0;
        let m = build_from(&ov, |_| (Vec::new(), 0), None, 0);
        assert!(m.bar.iter().all(|s| s.fraction == 0.0));
    }
}
