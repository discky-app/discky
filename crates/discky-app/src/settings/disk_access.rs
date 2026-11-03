//! Disk access: the Full Disk Access state and the folders the last scan could not read.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, StyledExt as _, h_flex, v_flex};
use gpui_kit::*;

use super::helpers::no_access_preview;
use super::model::{FDA_SETTINGS_URL, FdaStatus};
use super::{SettingsView, group_title, help, mono, page_title, row};
use crate::app::{AppState, Rescan};

/// How many unreadable folders the page lists.
const NO_ACCESS_LIMIT: usize = 50;

impl SettingsView {
    /// The Disk access page.
    pub(super) fn disk_access_page(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let theme = cx.theme();
        let (state, color) = match self.fda {
            None => ("checking…", theme.muted_foreground),
            Some(FdaStatus::Granted) => ("granted", theme.success),
            Some(FdaStatus::Denied) => ("not granted", theme.warning),
            Some(FdaStatus::Unknown) => ("unknown", theme.muted_foreground),
        };
        let no_access = cx
            .global::<AppState>()
            .engine
            .snapshot()
            .map(|s| s.meta.no_access.clone())
            .unwrap_or_default();
        let total = no_access.len();
        let (shown, rest) = no_access_preview(&no_access, &self.home, NO_ACCESS_LIMIT);
        let muted = theme.muted_foreground;
        v_flex()
            .gap_1()
            .child(page_title("Disk access"))
            .child(row(
                h_flex()
                    .gap_1()
                    .text_sm()
                    .child("Full Disk Access:")
                    .child(div().font_semibold().text_color(color).child(state)),
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("check-fda")
                            .ghost()
                            .small()
                            .label("Check again")
                            .on_click(cx.listener(|this, _, _, cx| this.check_fda(cx))),
                    )
                    .child(
                        Button::new("open-fda")
                            .small()
                            .label("Open System Settings")
                            .on_click(|_, _, cx| cx.open_url(FDA_SETTINGS_URL)),
                    ),
                cx,
            ))
            .child(help(
                "macOS does not let apps request it; grant it to Discky in Privacy & Security → \
                 Full Disk Access, then rescan.",
                cx,
            ))
            .child(
                h_flex()
                    .pt_2()
                    .gap_2()
                    .child(
                        group_title(format!("Folders the last scan could not read ({total})"))
                            .flex_1(),
                    )
                    .child(
                        Button::new("rescan")
                            .small()
                            .label("Rescan")
                            .on_click(|_, window, cx| window.dispatch_action(Box::new(Rescan), cx)),
                    ),
            )
            .children(shown.into_iter().map(|p| mono(p, cx).py_0p5()))
            .children((rest > 0).then(|| {
                div()
                    .text_sm()
                    .text_color(muted)
                    .child(format!("and {rest} more"))
            }))
    }
}
