//! Theme colours shared by the overview bar and the disk map.

use discky_core::rules::Category;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::{App, Hsla};

/// `chart_1..chart_5` for the first five categories in sidebar order, `chart_bullish` and
/// `warning` for the last two.
pub fn category_color(c: Category, cx: &App) -> Hsla {
    let t = cx.theme();
    match c {
        Category::Apps => t.chart_1,
        Category::AppCaches => t.chart_2,
        Category::Models => t.chart_3,
        Category::DevCaches => t.chart_4,
        Category::ProjectBuilds => t.chart_5,
        // The theme has five numbered chart colours. No red here: it would read as danger.
        Category::LanguageVersions => t.chart_bullish,
        Category::LargeOld => t.warning,
    }
}

/// One step of a sequential scale over `base`: bucket 0 is full strength, 5 the faintest.
pub fn sequential(base: Hsla, bucket: u8) -> Hsla {
    const OPACITY: [f32; 6] = [1.0, 0.8, 0.6, 0.45, 0.3, 0.15];
    base.opacity(OPACITY[usize::from(bucket.min(5))])
}
