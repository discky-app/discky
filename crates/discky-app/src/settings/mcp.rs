//! MCP server: the binary, the agent-delete switch, client snippets and the tool list.

use std::path::Path;

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::switch::Switch;
use gpui_kit::component::tab::{Tab, TabBar};
use gpui_kit::component::{
    ActiveTheme as _, IconName, Sizable as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::*;

use super::model::{CLIENTS, MCP_TOOLS};
use super::{SettingsView, group_title, help, mono, page_title, row};
use crate::format;

/// Width of the tool-name column.
const TOOL_NAME_WIDTH: f32 = 120.;

impl SettingsView {
    /// The MCP server page.
    pub(super) fn mcp_page(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let config = Self::config(cx);
        let binary: SharedString = match &self.mcp_binary {
            Some(p) => format!("{} found", format::home_relative(p, &self.home)).into(),
            None => "not found · brew install --cask discky-app/tap/discky or cargo install --path crates/discky-mcp".into(),
        };
        let bin = self
            .mcp_binary
            .clone()
            .unwrap_or_else(|| Path::new("discky-mcp").to_path_buf());
        let client = CLIENTS.get(self.client_ix).copied().unwrap_or(CLIENTS[0]);
        let snippet = client.snippet(&bin);
        let theme = cx.theme();
        let (border, muted_bg, muted) = (theme.border, theme.muted, theme.muted_foreground);
        let mono_font = theme.mono_font_family.clone();
        let tools = MCP_TOOLS.iter().map(|(name, purpose)| {
            h_flex()
                .items_start()
                .gap_3()
                .py_1()
                .border_b_1()
                .border_color(border)
                .child(
                    div()
                        .flex_shrink_0()
                        .w(px(TOOL_NAME_WIDTH))
                        .font_family(mono_font.clone())
                        .text_sm()
                        .child(*name),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_sm()
                        .text_color(muted)
                        .child(*purpose),
                )
        });
        v_flex()
            .gap_1()
            .child(page_title("MCP server"))
            .child(help(
                "The same core as the app, over stdio. Connect it to an agent and ask what is \
                 eating the disk.",
                cx,
            ))
            .child(row(
                v_flex()
                    .child(div().text_sm().child("Binary"))
                    .child(mono(binary, cx).text_color(muted)),
                div(),
                cx,
            ))
            .child(row(
                v_flex()
                    .child(div().text_sm().child("Allow the agent to delete"))
                    .child(help(
                        "Off: the agent scans and plans only. On: it may call execute_plan \
                         (non-interactive steps only).",
                        cx,
                    )),
                Switch::new("allow-agent-delete")
                    .checked(config.mcp.allow_agent_delete)
                    .on_click(cx.listener(|this, on: &bool, window, cx| {
                        let on = *on;
                        this.save(|c| c.mcp.allow_agent_delete = on, window, cx);
                    })),
                cx,
            ))
            .child(group_title("Connect to your agent"))
            .child(
                TabBar::new("mcp-clients")
                    .underline()
                    .small()
                    .selected_index(self.client_ix)
                    .children(CLIENTS.iter().map(|c| Tab::new().label(c.label())))
                    .on_click(cx.listener(|this, ix: &usize, _, cx| {
                        this.client_ix = *ix;
                        cx.notify();
                    })),
            )
            .child(
                h_flex()
                    .items_start()
                    .gap_2()
                    .p_3()
                    .rounded(cx.theme().radius)
                    .border_1()
                    .border_color(border)
                    .bg(muted_bg)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .whitespace_normal()
                            .child(mono(snippet.clone(), cx)),
                    )
                    .child(
                        Button::new("copy-snippet")
                            .ghost()
                            .small()
                            .icon(IconName::Copy)
                            .label("Copy")
                            .on_click(move |_, window, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(snippet.clone()));
                                window.push_notification(Notification::info("Copied"), cx);
                            }),
                    ),
            )
            .child(group_title("Tools the agent gets"))
            .children(tools)
    }
}
