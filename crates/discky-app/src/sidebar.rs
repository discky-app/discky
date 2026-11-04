//! The left sidebar: Overview, the finding categories with their weights, Disk, Settings.

use discky_core::rules::Category;
use gpui_kit::component::sidebar::{
    Sidebar, SidebarGroup, SidebarItem, SidebarMenu, SidebarMenuItem,
};
use gpui_kit::component::{ActiveTheme as _, Collapsible};
use gpui_kit::*;

use crate::app::{AppView, Route};
use crate::format;

/// Sidebar width in pixels (spec §11).
pub const SIDEBAR_WIDTH: f32 = 212.;

/// The finding categories in sidebar order.
pub const CATEGORIES: [Category; 7] = [
    Category::Apps,
    Category::AppCaches,
    Category::Models,
    Category::DevCaches,
    Category::ProjectBuilds,
    Category::LanguageVersions,
    Category::LargeOld,
];

/// The weight shown next to a category: its size, or "—" when nothing was found.
pub fn weight_label(bytes: u64) -> String {
    if bytes == 0 {
        "—".to_string()
    } else {
        format::bytes(bytes)
    }
}

/// The label next to `cat`: for Applications the number of apps not opened in 6 months
/// (`Overview::apps_unused`, "—" for none), for the others [`weight_label`] of its bytes.
pub fn category_label(cat: Category, weights: &[(Category, u64)], apps_unused: usize) -> String {
    match cat {
        Category::Apps if apps_unused == 0 => "—".to_string(),
        Category::Apps => apps_unused.to_string(),
        _ => weight_label(weight_of(weights, cat)),
    }
}

/// Bytes recorded for `cat` in an `Overview::by_category` list (0 when absent).
fn weight_of(weights: &[(Category, u64)], cat: Category) -> u64 {
    weights
        .iter()
        .find(|(c, _)| *c == cat)
        .map_or(0, |(_, b)| *b)
}

/// Build the sidebar for `route`, with `weights` from `Overview::by_category` and
/// `apps_unused` from `Overview::apps_unused`. Clicks call [`AppView::navigate`] on `view`.
pub fn sidebar(
    route: Route,
    weights: &[(Category, u64)],
    apps_unused: usize,
    collapsed: bool,
    view: WeakEntity<AppView>,
) -> Sidebar<Section> {
    let item = |label: SharedString, target: Route| {
        let view = view.clone();
        SidebarMenuItem::new(label)
            .active(route == target)
            .on_click(move |_, _, cx| {
                // The view is gone only while its window closes; nothing to navigate then.
                let _ = view.update(cx, |v, cx| v.navigate(target, cx));
            })
    };

    let overview = SidebarMenu::new().child(item("Overview".into(), Route::Overview));
    let findings = SidebarGroup::new("Findings").child(SidebarMenu::new().children(
        CATEGORIES.iter().map(|&cat| {
            let label = category_label(cat, weights, apps_unused);
            item(cat.to_string().into(), Route::Category(cat)).suffix(move |_, cx| {
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(label.clone())
            })
        }),
    ));
    let disk = SidebarGroup::new("Disk")
        .child(SidebarMenu::new().child(item("Disk map".into(), Route::Map)));
    let settings = SidebarMenu::new().child(item("Settings".into(), Route::Settings));

    Sidebar::new("main")
        .w(px(SIDEBAR_WIDTH))
        .collapsed(collapsed)
        .child(Section::Menu(Box::new(overview)))
        .child(Section::Group(findings))
        .child(Section::Group(disk))
        .footer(Footer(settings))
}

/// One block of the sidebar: a bare menu (Overview) or a labelled group. `Sidebar` takes
/// children of a single type, so this enum lets both sit in it.
#[derive(Clone)]
pub enum Section {
    /// A menu without a group label (boxed: a menu is much larger than a group).
    Menu(Box<SidebarMenu>),
    /// A labelled group of menus.
    Group(SidebarGroup<SidebarMenu>),
}

impl Collapsible for Section {
    fn collapsed(self, collapsed: bool) -> Self {
        match self {
            Section::Menu(m) => Section::Menu(Box::new(m.collapsed(collapsed))),
            Section::Group(g) => Section::Group(g.collapsed(collapsed)),
        }
    }

    fn is_collapsed(&self) -> bool {
        match self {
            Section::Menu(m) => m.is_collapsed(),
            Section::Group(g) => g.is_collapsed(),
        }
    }
}

impl SidebarItem for Section {
    fn render(
        self,
        id: impl Into<ElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> impl IntoElement {
        match self {
            Section::Menu(m) => (*m).render(id, window, cx).into_any_element(),
            Section::Group(g) => g.render(id, window, cx).into_any_element(),
        }
    }
}

/// The sidebar footer (the Settings item), rendered with the same look as the menus above.
#[derive(IntoElement)]
struct Footer(SidebarMenu);

impl RenderOnce for Footer {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        div()
            .w_full()
            .p_3()
            .child(self.0.render("footer", window, cx))
    }
}

#[cfg(test)]
mod tests {
    // Not `use super::*`: the GPUI glob brings a `test` attribute macro that shadows std's.
    use super::{category_label, weight_label, weight_of};
    use discky_core::rules::Category;

    #[test]
    fn applications_show_the_unused_count() {
        let w = [(Category::Apps, 9_100_000_000), (Category::Models, 5_000)];
        assert_eq!(category_label(Category::Apps, &w, 19), "19");
        assert_eq!(category_label(Category::Apps, &w, 0), "—");
        assert_eq!(category_label(Category::Models, &w, 19), "5 KB");
    }

    #[test]
    fn zero_weight_is_a_dash() {
        assert_eq!(weight_label(0), "—");
        assert_eq!(weight_label(9_100_000_000), "9.1 GB");
    }

    #[test]
    fn missing_category_weighs_nothing() {
        let w = [(Category::Models, 5)];
        assert_eq!(weight_of(&w, Category::Models), 5);
        assert_eq!(weight_of(&w, Category::Apps), 0);
    }
}
