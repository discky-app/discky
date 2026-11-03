//! Version manager: which manager the Language versions category reads (mise only).

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use gpui_kit::*;

use super::model::REPO_URL;
use super::{SettingsView, help, page_title, row};
use crate::category::table::pill;
use crate::format;

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
}
