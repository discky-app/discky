//! Version manager: which manager the Language versions category reads (mise only), and
//! a dry run of `mise prune`.

use discky_core::rules::Category;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Sizable as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::*;

use super::model::REPO_URL;
use super::{SettingsView, help, page_title, row};
use crate::app::{AppState, Route};
use crate::category::table::pill;
use crate::format;

/// Width of the "What mise would prune" dialog.
const PRUNE_DIALOG_WIDTH: f32 = 560.;
/// Tallest the dialog's output grows before it scrolls.
const PRUNE_OUTPUT_MAX_HEIGHT: f32 = 320.;

impl SettingsView {
    /// The Version manager page.
    pub(super) fn version_manager_page(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let status: SharedString = match &self.mise {
            None => "Checking for mise…".into(),
            Some(None) => "mise is not installed · brew install mise".into(),
            Some(Some(info)) => match &info.data_dir {
                Some(dir) => format!(
                    "mise {} · {}",
                    info.version,
                    format::home_relative(dir, &self.home)
                )
                .into(),
                None => format!("mise {}", info.version).into(),
            },
        };
        let no_mise = matches!(self.mise, Some(None));
        let app = self.app.clone();
        v_flex()
            .gap_1()
            .child(page_title("Version manager"))
            .child(help("Which manager Language versions shows.", cx))
            .child(row(
                div().text_sm().child(status),
                pill("mise", cx.theme().primary),
                cx,
            ))
            .child(
                v_flex()
                    .pt_2()
                    .gap_1()
                    .items_start()
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new("mise-prune")
                                    .small()
                                    .label(if self.prune_running {
                                        "Running…"
                                    } else {
                                        "mise prune (dry run)"
                                    })
                                    .disabled(self.prune_running || no_mise)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.prune_dry_run(window, cx)
                                    })),
                            )
                            .child(
                                Button::new("show-versions")
                                    .ghost()
                                    .small()
                                    .label("Show installed versions")
                                    .on_click(move |_, _, cx| {
                                        let to = Route::Category(Category::LanguageVersions);
                                        let _ = app.update(cx, |v, cx| v.navigate(to, cx));
                                    }),
                            ),
                    )
                    .child(help("Runs `mise prune -n`; nothing is removed.", cx)),
            )
            .child(
                h_flex()
                    .pt_2()
                    .gap_1()
                    .text_sm()
                    .child("Need another one (nvm, rbenv, pyenv, asdf)?")
                    .child(
                        Button::new("open-issue")
                            .link()
                            .small()
                            .label("Open an issue on GitHub.")
                            .on_click(|_, _, cx| cx.open_url(&format!("{REPO_URL}/issues"))),
                    ),
            )
    }

    /// Run `mise prune -n` off the main thread; show its output in a dialog, or why it
    /// failed in a toast.
    fn prune_dry_run(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.prune_running {
            return;
        }
        self.prune_running = true;
        let engine = cx.global::<AppState>().engine.clone();
        let work = cx.background_spawn(async move { engine.mise_prune_dry_run() });
        self._prune_task = cx.spawn_in(window, async move |this, cx| {
            let result = work.await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.prune_running = false;
                match result {
                    Ok(out) => open_prune_dialog(prune_text(&out).into(), window, cx),
                    Err(msg) => window.push_notification(Notification::warning(msg), cx),
                }
                cx.notify();
            });
        });
        cx.notify();
    }
}

/// What the dialog shows for `mise prune -n` output `out`.
fn prune_text(out: &str) -> String {
    match out.trim_end() {
        "" => "Nothing to prune.".to_string(),
        text => text.to_string(),
    }
}

/// The "What mise would prune" dialog showing `text` in a scrollable mono block.
fn open_prune_dialog(text: SharedString, window: &mut Window, cx: &mut App) {
    window.open_dialog(cx, move |dialog, _, cx| {
        let theme = cx.theme();
        dialog
            .title("What mise would prune")
            .w(px(PRUNE_DIALOG_WIDTH))
            .child(
                div()
                    .id("mise-prune-output")
                    .p_2()
                    .max_h(px(PRUNE_OUTPUT_MAX_HEIGHT))
                    .rounded(theme.radius)
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.muted)
                    .font_family(theme.mono_font_family.clone())
                    .text_xs()
                    .overflow_y_scrollbar()
                    .child(text.clone()),
            )
            .footer(
                h_flex().w_full().justify_end().child(
                    Button::new("mise-prune-close")
                        .label("Close")
                        .on_click(|_, window, cx| window.close_dialog(cx)),
                ),
            )
    });
}

#[cfg(test)]
mod tests {
    use super::prune_text;

    #[test]
    fn empty_prune_output_says_nothing_to_prune() {
        assert_eq!(prune_text(""), "Nothing to prune.");
        assert_eq!(prune_text("\n"), "Nothing to prune.");
        assert_eq!(
            prune_text("mise would prune node@18.0.0\n"),
            "mise would prune node@18.0.0"
        );
    }
}
