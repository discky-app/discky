//! The Settings screen (mockup `05-settings-mcp.html`, spec §11): a section list on the
//! left and one page per section on the right. Every control saves at once through
//! [`SettingsView::save`].

mod about;
mod disk_access;
pub mod helpers;
mod mcp;
pub mod model;
mod removal;
mod scanning;
mod version_manager;

use std::path::PathBuf;

use discky_core::Config;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::notification::Notification;
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::{
    ActiveTheme as _, Selectable as _, Sizable as _, StyledExt as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::*;

use crate::app::{AppState, AppView};
use helpers::threshold_field_text;
use model::{FdaStatus, MiseInfo};

/// Width of the section list.
const SECTION_LIST_WIDTH: f32 = 180.;
/// Widest a page's content grows.
const PAGE_MAX_WIDTH: f32 = 640.;

/// One page of Settings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Scanning,
    Removal,
    VersionManager,
    Mcp,
    DiskAccess,
    About,
}

/// All sections, in list order.
pub const SECTIONS: [Section; 6] = [
    Section::Scanning,
    Section::Removal,
    Section::VersionManager,
    Section::Mcp,
    Section::DiskAccess,
    Section::About,
];

impl Section {
    /// The name shown in the section list.
    pub fn label(self) -> &'static str {
        match self {
            Section::Scanning => "Scanning",
            Section::Removal => "Removal",
            Section::VersionManager => "Version manager",
            Section::Mcp => "MCP server",
            Section::DiskAccess => "Disk access",
            Section::About => "About",
        }
    }

    /// The section named `name` in snake case (`disk_access`, `mcp`, …).
    pub fn parse(name: &str) -> Option<Section> {
        Some(match name {
            "scanning" => Section::Scanning,
            "removal" => Section::Removal,
            "version_manager" => Section::VersionManager,
            "mcp" => Section::Mcp,
            "disk_access" => Section::DiskAccess,
            "about" => Section::About,
            _ => return None,
        })
    }
}

/// The Settings screen. It holds only view state; the settings themselves are read from
/// `Engine::config()` on every render, so a failed save shows the stored values again.
pub struct SettingsView {
    section: Section,
    /// The main view, for links that open another screen.
    app: WeakEntity<AppView>,
    home: PathBuf,
    /// "Files larger than [MB]".
    large_input: Entity<InputState>,
    /// "Untouched for [days]".
    old_input: Entity<InputState>,
    /// New exclude pattern.
    exclude_input: Entity<InputState>,
    /// Why the typed size threshold was not applied.
    large_error: Option<SharedString>,
    /// Why the typed age threshold was not applied.
    old_error: Option<SharedString>,
    /// Selected tab of the MCP client snippets.
    client_ix: usize,
    /// The `discky-mcp` binary, found once when the screen is built.
    mcp_binary: Option<PathBuf>,
    /// Full Disk Access probe result; `None` while probing.
    fda: Option<FdaStatus>,
    /// `mise --version` result; outer `None` while checking.
    mise: Option<Option<MiseInfo>>,
    /// `mise prune -n` is running.
    prune_running: bool,
    _fda_task: Task<()>,
    _mise_task: Task<()>,
    _prune_task: Task<()>,
    _subscriptions: Vec<Subscription>,
}

impl SettingsView {
    /// Build the screen showing `section`; the inputs start from the stored config.
    pub fn new(
        section: Section,
        app: WeakEntity<AppView>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let home = discky_core::paths::home_dir().unwrap_or_default();
        let config = cx.global::<AppState>().engine.config();
        let large_text = threshold_field_text(config.thresholds.large_file_bytes);
        let large_input = cx.new(|cx| InputState::new(window, cx).default_value(large_text));
        let old_days = config.thresholds.old_days.to_string();
        let old_input = cx.new(|cx| InputState::new(window, cx).default_value(old_days));
        let exclude_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("e.g. **/node_modules"));
        let subscriptions = vec![
            cx.subscribe_in(
                &large_input,
                window,
                |this, _, ev: &InputEvent, window, cx| {
                    if applies(ev) {
                        this.apply_large(window, cx);
                    }
                },
            ),
            cx.subscribe_in(
                &old_input,
                window,
                |this, _, ev: &InputEvent, window, cx| {
                    if applies(ev) {
                        this.apply_old(window, cx);
                    }
                },
            ),
            cx.subscribe_in(
                &exclude_input,
                window,
                |this, _, ev: &InputEvent, window, cx| {
                    if matches!(ev, InputEvent::PressEnter { .. }) {
                        this.add_exclude(window, cx);
                    }
                },
            ),
        ];
        let exe = std::env::current_exe().ok();
        let mcp_binary = model::find_mcp_binary(&home, exe.as_deref());
        let mut view = SettingsView {
            section,
            app,
            home,
            large_input,
            old_input,
            exclude_input,
            large_error: None,
            old_error: None,
            client_ix: 0,
            mcp_binary,
            fda: None,
            mise: None,
            prune_running: false,
            _fda_task: Task::ready(()),
            _mise_task: Task::ready(()),
            _prune_task: Task::ready(()),
            _subscriptions: subscriptions,
        };
        view.on_shown(cx);
        view
    }

    /// Show `section` and refresh what that page probes.
    pub fn set_section(&mut self, section: Section, cx: &mut Context<Self>) {
        self.section = section;
        self.on_shown(cx);
        cx.notify();
    }

    /// The screen (or its section) became visible: re-run the current page's probes.
    pub fn on_shown(&mut self, cx: &mut Context<Self>) {
        match self.section {
            Section::DiskAccess => self.check_fda(cx),
            Section::VersionManager => self.check_mise(cx),
            _ => {}
        }
    }

    /// Probe Full Disk Access off the main thread.
    fn check_fda(&mut self, cx: &mut Context<Self>) {
        self.fda = None;
        let home = self.home.clone();
        let work = cx.background_spawn(async move { model::probe_fda(&home) });
        self._fda_task = cx.spawn(async move |this, cx| {
            let status = work.await;
            let _ = this.update(cx, |this, cx| {
                this.fda = Some(status);
                cx.notify();
            });
        });
        cx.notify();
    }

    /// Run `mise --version` off the main thread.
    fn check_mise(&mut self, cx: &mut Context<Self>) {
        self.mise = None;
        let home = self.home.clone();
        let work = cx.background_spawn(async move { model::mise_info(&home) });
        self._mise_task = cx.spawn(async move |this, cx| {
            let info = work.await;
            let _ = this.update(cx, |this, cx| {
                this.mise = Some(info);
                cx.notify();
            });
        });
        cx.notify();
    }

    /// The stored settings.
    fn config(cx: &App) -> Config {
        cx.global::<AppState>().engine.config()
    }

    /// Apply `f` to a copy of the stored config and save it at once. On failure, say so
    /// in a toast and show the stored values again. Returns whether the save succeeded.
    fn save(
        &mut self,
        f: impl FnOnce(&mut Config),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let engine = cx.global::<AppState>().engine.clone();
        let mut config = engine.config();
        f(&mut config);
        let saved = match engine.set_config(config) {
            Ok(()) => true,
            Err(e) => {
                window.push_notification(
                    Notification::error(format!("Could not save settings: {e}")),
                    cx,
                );
                self.reload(window, cx);
                false
            }
        };
        cx.notify();
        saved
    }

    /// Reset the view state that copies the config (the threshold fields) to the stored
    /// values.
    fn reload(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let config = Self::config(cx);
        let large = threshold_field_text(config.thresholds.large_file_bytes);
        let old = config.thresholds.old_days.to_string();
        self.large_input
            .update(cx, |s, cx| s.set_value(large, window, cx));
        self.old_input
            .update(cx, |s, cx| s.set_value(old, window, cx));
        self.large_error = None;
        self.old_error = None;
    }

    /// Apply the typed size threshold, or explain why it is not valid.
    fn apply_large(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.large_input.read(cx).value().to_string();
        let Some(bytes) = model::parse_mb(&text) else {
            self.large_error = Some("Enter a whole number of megabytes above 0".into());
            cx.notify();
            return;
        };
        self.large_error = None;
        let stored = Self::config(cx).thresholds.large_file_bytes;
        // The field shows rounded megabytes; an untouched field keeps the exact value.
        if text.trim() == threshold_field_text(stored) {
            cx.notify();
            return;
        }
        self.save(|c| c.thresholds.large_file_bytes = bytes, window, cx);
    }

    /// Apply the typed age threshold, or explain why it is not valid.
    fn apply_old(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.old_input.read(cx).value().to_string();
        let Some(days) = model::parse_days(&text) else {
            self.old_error = Some("Enter a whole number of days above 0".into());
            cx.notify();
            return;
        };
        self.old_error = None;
        if Self::config(cx).thresholds.old_days == days {
            cx.notify();
            return;
        }
        self.save(|c| c.thresholds.old_days = days, window, cx);
    }

    /// Add the typed exclude pattern; an invalid glob is reported in a toast.
    fn add_exclude(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.exclude_input.read(cx).value().to_string();
        let mut list = Self::config(cx).scan.exclude;
        match helpers::add_exclude(&mut list, &text) {
            Err(e) => {
                window.push_notification(Notification::error(format!("Invalid pattern: {e}")), cx)
            }
            Ok(false) => self.clear_exclude_input(window, cx),
            Ok(true) => {
                if self.save(|c| c.scan.exclude = list, window, cx) {
                    self.clear_exclude_input(window, cx);
                }
            }
        }
    }

    fn clear_exclude_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.exclude_input
            .update(cx, |s, cx| s.set_value("", window, cx));
    }

    /// Ask for folders and add the new ones to the scan roots.
    fn pick_roots(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: true,
            prompt: None,
        });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(paths))) = picked.await else {
                return;
            };
            let _ = this.update_in(cx, |this, window, cx| {
                let mut roots = Self::config(cx).scan.roots;
                let before = roots.len();
                for p in paths {
                    helpers::add_root(&mut roots, p);
                }
                if roots.len() > before {
                    this.save(|c| c.scan.roots = roots, window, cx);
                }
            });
        })
        .detach();
    }

    /// The left column: one ghost button per section, the current one selected.
    fn section_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .flex_shrink_0()
            .w(px(SECTION_LIST_WIDTH))
            .h_full()
            .p_2()
            .gap_0p5()
            .border_r_1()
            .border_color(cx.theme().border)
            .children(SECTIONS.iter().map(|&s| {
                Button::new(("settings-section", s as usize))
                    .ghost()
                    .small()
                    .w_full()
                    // The kit centres a button's content; a growing child left-aligns it.
                    .child(div().flex_1().child(s.label()))
                    .selected(self.section == s)
                    .on_click(cx.listener(move |this, _, _, cx| this.set_section(s, cx)))
            }))
    }
}

/// Whether an input event commits a threshold field (Enter or leaving the field).
fn applies(ev: &InputEvent) -> bool {
    matches!(ev, InputEvent::PressEnter { .. } | InputEvent::Blur)
}

/// A page's heading.
fn page_title(text: &'static str) -> Div {
    div().text_lg().font_semibold().child(text)
}

/// A group heading inside a page.
fn group_title(text: impl Into<SharedString>) -> Div {
    div().pt_2().text_sm().font_semibold().child(text.into())
}

/// Muted help text.
fn help(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .text_sm()
        .text_color(cx.theme().muted_foreground)
        .child(text.into())
}

/// A settings row: `label` (and anything under it) on the left, `control` on the right.
fn row(label: impl IntoElement, control: impl IntoElement, cx: &App) -> Div {
    h_flex()
        .gap_4()
        .py_2()
        .border_b_1()
        .border_color(cx.theme().border)
        .child(v_flex().flex_1().min_w_0().gap_0p5().child(label))
        .child(div().flex_shrink_0().child(control))
}

/// Mono text, for paths, commands and snippets.
fn mono(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .font_family(cx.theme().mono_font_family.clone())
        .text_sm()
        .child(text.into())
}

impl Render for SettingsView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let page = match self.section {
            Section::Scanning => self.scanning_page(cx).into_any_element(),
            Section::Removal => self.removal_page(cx).into_any_element(),
            Section::VersionManager => self.version_manager_page(cx).into_any_element(),
            Section::Mcp => self.mcp_page(cx).into_any_element(),
            Section::DiskAccess => self.disk_access_page(window, cx).into_any_element(),
            Section::About => about::page(cx).into_any_element(),
        };
        h_flex()
            .size_full()
            .min_h_0()
            .items_start()
            .child(self.section_list(cx))
            .child(
                div()
                    .id("settings-page")
                    .flex_1()
                    .h_full()
                    .min_w_0()
                    .overflow_y_scrollbar()
                    .child(v_flex().p_6().gap_3().max_w(px(PAGE_MAX_WIDTH)).child(page)),
            )
    }
}

#[cfg(test)]
mod tests {
    // Not `use super::*`: the GPUI glob brings a `test` attribute macro that shadows std's.
    use super::{SECTIONS, Section};

    #[test]
    fn section_names_parse() {
        let names = [
            "scanning",
            "removal",
            "version_manager",
            "mcp",
            "disk_access",
            "about",
        ];
        for (name, s) in names.iter().zip(SECTIONS) {
            assert_eq!(Section::parse(name), Some(s));
        }
        assert_eq!(Section::parse("nope"), None);
    }
}
