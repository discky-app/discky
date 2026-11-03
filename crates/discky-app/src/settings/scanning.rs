//! Scanning: roots, exclude patterns and the large/old thresholds.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use super::{SettingsView, group_title, help, mono, page_title, row};
use crate::format;

impl SettingsView {
    /// The Scanning page.
    pub(super) fn scanning_page(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let config = Self::config(cx);
        let last_root = config.scan.roots.len() <= 1;
        let roots = config.scan.roots.iter().enumerate().map(|(ix, root)| {
            let root = root.clone();
            row(
                mono(format::home_relative(&root, &self.home), cx),
                Button::new(("remove-root", ix))
                    .ghost()
                    .small()
                    .label("Remove")
                    .disabled(last_root)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        let root = root.clone();
                        this.save(
                            |c| {
                                if c.scan.roots.len() > 1 {
                                    c.scan.roots.retain(|r| r != &root);
                                }
                            },
                            window,
                            cx,
                        );
                    })),
                cx,
            )
        });
        let excludes = config.scan.exclude.iter().enumerate().map(|(ix, pattern)| {
            let pattern = pattern.clone();
            row(
                mono(pattern.clone(), cx),
                Button::new(("remove-exclude", ix))
                    .ghost()
                    .small()
                    .label("Remove")
                    .on_click(cx.listener(move |this, _, window, cx| {
                        let pattern = pattern.clone();
                        this.save(|c| c.scan.exclude.retain(|p| p != &pattern), window, cx);
                    })),
                cx,
            )
        });
        v_flex()
            .gap_1()
            .child(page_title("Scanning"))
            .child(group_title("Roots"))
            .children(roots)
            .child(
                h_flex().pt_1().child(
                    Button::new("add-root")
                        .small()
                        .label("Add folder…")
                        .on_click(cx.listener(|this, _, window, cx| this.pick_roots(window, cx))),
                ),
            )
            .child(group_title("Exclude patterns"))
            .child(help("One glob per entry, e.g. **/node_modules.", cx))
            .children(excludes)
            .child(
                h_flex()
                    .pt_1()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .child(Input::new(&self.exclude_input).small()),
                    )
                    .child(
                        Button::new("add-exclude").small().label("Add").on_click(
                            cx.listener(|this, _, window, cx| this.add_exclude(window, cx)),
                        ),
                    ),
            )
            .child(group_title("Large & old"))
            .child(threshold_row(
                "Files larger than",
                "MB",
                &self.large_input,
                self.large_error.clone(),
                cx,
            ))
            .child(threshold_row(
                "Untouched for",
                "days",
                &self.old_input,
                self.old_error.clone(),
                cx,
            ))
            .child(help("Applies to the next scan", cx))
    }
}

/// "<label> [input] <unit>", with `error` under it in the danger colour.
fn threshold_row(
    label: &'static str,
    unit: &'static str,
    input: &Entity<InputState>,
    error: Option<SharedString>,
    cx: &App,
) -> Div {
    let danger = cx.theme().danger;
    row(
        div().text_sm().child(label).when_some(error, |this, e| {
            this.child(div().text_xs().text_color(danger).child(e))
        }),
        h_flex()
            .gap_2()
            .child(div().w(px(96.)).child(Input::new(input).small()))
            .child(div().text_sm().child(unit)),
        cx,
    )
}
