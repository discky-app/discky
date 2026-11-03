//! About: logo, version, tagline and links.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, StyledExt as _, h_flex, v_flex};
use gpui_kit::*;

use super::model::{DONATE_URL, REPO_URL};
use crate::duck::logo_element;

/// The About page.
pub(super) fn page(cx: &App) -> impl IntoElement {
    let muted = cx.theme().muted_foreground;
    v_flex()
        .items_center()
        .gap_2()
        .py_6()
        .child(logo_element(96.))
        .child(
            div()
                .text_lg()
                .font_semibold()
                .child(format!("Discky {}", env!("CARGO_PKG_VERSION"))),
        )
        .child(
            div()
                .text_sm()
                .text_color(muted)
                .child("Finds what is eating your Mac's disk and removes it safely."),
        )
        .child(
            h_flex()
                .gap_3()
                .child(
                    Button::new("about-github")
                        .link()
                        .label("GitHub")
                        .on_click(|_, _, cx| cx.open_url(REPO_URL)),
                )
                .children(DONATE_URL.map(|url| {
                    Button::new("about-donate")
                        .link()
                        .label("Donate")
                        .on_click(move |_, _, cx| cx.open_url(url))
                })),
        )
        .child(div().text_sm().text_color(muted).child("MIT License"))
}
