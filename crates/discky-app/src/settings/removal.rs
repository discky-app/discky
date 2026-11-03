//! Removal: Trash or permanent, the empty-Trash reminder, the removal log.

use discky_core::config::RemovalMode;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::tab::{Tab, TabBar};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, v_flex};
use gpui_kit::*;

use super::helpers::{removal_mode_from_index, removal_mode_index};
use super::{SettingsView, help, mono, page_title, row};
use crate::app::AppState;
use crate::format;

impl SettingsView {
    /// The Removal page.
    pub(super) fn removal_page(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let config = Self::config(cx);
        let mode = config.removal.mode;
        let log = cx.global::<AppState>().engine.paths().log.clone();
        let theme = cx.theme();
        let (description, description_color) = match mode {
            RemovalMode::Trash => (
                "Can be undone; space is freed when the Trash is emptied",
                theme.muted_foreground,
            ),
            RemovalMode::Permanent => ("Cannot be undone", theme.warning),
        };
        v_flex()
            .gap_1()
            .child(page_title("Removal"))
            .child(help(
                "Applies to files and folders Discky removes itself. Tools (brew, mise, ollama, \
                 cargo…) remove things their own way.",
                cx,
            ))
            .child(
                v_flex()
                    .py_2()
                    .gap_1()
                    .child(
                        TabBar::new("removal-mode")
                            .segmented()
                            .small()
                            .selected_index(removal_mode_index(mode))
                            .child(Tab::new().label("Move to Trash"))
                            .child(Tab::new().label("Delete permanently (rm)"))
                            .on_click(cx.listener(|this, ix: &usize, window, cx| {
                                if let Some(mode) = removal_mode_from_index(*ix) {
                                    this.save(|c| c.removal.mode = mode, window, cx);
                                }
                            })),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(description_color)
                            .child(description),
                    ),
            )
            .child(row(
                div().text_sm().child("Remind me to empty the Trash"),
                Switch::new("remind-trash")
                    .checked(config.removal.remind_trash)
                    .on_click(cx.listener(|this, on: &bool, window, cx| {
                        let on = *on;
                        this.save(|c| c.removal.remind_trash = on, window, cx);
                    })),
                cx,
            ))
            .child(row(
                div().text_sm().child("Show commands before running"),
                help("Always. Cannot be turned off.", cx),
                cx,
            ))
            .child(row(
                v_flex()
                    .child(div().text_sm().child("Removal log"))
                    .child(mono(format::home_relative(&log, &self.home), cx)),
                Button::new("reveal-log")
                    .ghost()
                    .small()
                    .label("Reveal")
                    .on_click(move |_, _, cx| {
                        // A log not written yet: show its folder instead.
                        let target = if log.exists() {
                            log.as_path()
                        } else {
                            log.parent().unwrap_or(log.as_path())
                        };
                        cx.reveal_path(target);
                    }),
                cx,
            ))
    }
}
