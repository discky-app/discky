//! The Full Disk Access notices on the Overview: onboarding, relaunch and the banner.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{
    ActiveTheme as _, Icon, IconName, Sizable as _, StyledExt as _, h_flex, v_flex,
};
use gpui_kit::*;

use super::{OverviewView, rescan_button};
use crate::access;
use crate::duck::logo_element;

impl OverviewView {
    /// Shown instead of "No scan yet" while access is denied and nothing was scanned.
    pub(super) fn onboarding_card(&self, cx: &App) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        v_flex()
            .flex_1()
            .items_center()
            .justify_center()
            .gap_4()
            .py_16()
            .child(logo_element(128.))
            .child(
                div()
                    .text_xl()
                    .font_semibold()
                    .child("Give Discky Full Disk Access"),
            )
            .child(
                v_flex()
                    .max_w(px(520.))
                    .gap_3()
                    .text_sm()
                    .child(
                        "Without it macOS hides Mail, Safari and other apps' containers from \
                         the scan. macOS does not let apps ask for it.",
                    )
                    .child(
                        v_flex()
                            .gap_1()
                            .text_color(muted)
                            .child(
                                "1. Open the settings pane below. Discky is usually already in \
                                 the list, switched off, because it just tried to read \
                                 ~/Library.",
                            )
                            .child(
                                "2. Turn it on. If it is not listed, drag Discky.app from the \
                                 Finder window that opens next to it.",
                            )
                            .child(
                                "3. Come back here: Discky notices the change and offers to \
                                 relaunch.",
                            ),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("open-fda")
                            .primary()
                            .label("Open Full Disk Access settings")
                            .on_click(|_, _, cx| access::open_fda_settings(cx)),
                    )
                    .child(rescan_button("scan-anyway", "Scan anyway").ghost()),
            )
    }

    /// Access was granted after being seen denied: the running process still lacks it.
    pub(super) fn relaunch_card(&self, cx: &App) -> impl IntoElement {
        let theme = cx.theme();
        h_flex()
            .gap_4()
            .p_4()
            .rounded(theme.radius_lg)
            .border_1()
            .border_color(theme.border)
            .child(
                v_flex()
                    .flex_1()
                    .gap_1()
                    .child(div().font_semibold().child("Full Disk Access granted"))
                    .child(
                        div().text_sm().text_color(theme.muted_foreground).child(
                            "macOS applies it to a new process. Relaunch Discky, then scan.",
                        ),
                    ),
            )
            .child(
                Button::new("relaunch")
                    .primary()
                    .label("Relaunch Discky")
                    .on_click(|_, window, cx| crate::app::relaunch_app(window, cx)),
            )
    }

    /// Access is denied and a snapshot exists: the warning row, until dismissed.
    pub(super) fn access_banner(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let text = match self.model.no_access {
            0 => "Full Disk Access is off: parts of ~/Library were skipped.".to_string(),
            n => format!("Full Disk Access is off: {n} folders were skipped."),
        };
        h_flex()
            .gap_2()
            .px_3()
            .py_2()
            .rounded(theme.radius)
            .border_1()
            .border_color(theme.warning)
            .bg(theme.warning.opacity(0.1))
            .text_sm()
            .child(Icon::new(IconName::TriangleAlert).text_color(theme.warning))
            .child(div().flex_1().child(text))
            .child(
                Button::new("banner-open-fda")
                    .small()
                    .label("Open settings")
                    .on_click(|_, _, cx| access::open_fda_settings(cx)),
            )
            .child(
                Button::new("banner-dismiss")
                    .ghost()
                    .small()
                    .icon(Icon::new(IconName::Close))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.banner_dismissed = true;
                        cx.notify();
                    })),
            )
    }
}
