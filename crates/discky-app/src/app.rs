//! Application state, routes, actions and menus; the main window shell and the startup
//! error window.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use discky_core::index::snapshot::Actor;
use discky_core::paths::display;
use discky_core::rules::Category;
use discky_core::{
    Config, ConfigError, DisckyPaths, Engine, EngineError, EngineOptions, ScanStatus,
};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input;
use gpui_kit::component::notification::Notification;
use gpui_kit::component::{
    ActiveTheme as _, Sizable as _, StyledExt as _, Theme, TitleBar, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::format;
use crate::overview::OverviewView;
use crate::scan::{ScanController, ScanMsg};
use crate::sidebar;

gpui_kit::actions!(
    discky,
    [
        /// Start a new scan of the configured roots.
        Rescan,
        /// Show the Settings screen.
        OpenSettings,
        /// Show the About page.
        About,
        /// Quit Discky.
        Quit,
        /// Show and focus the category filter.
        FocusFilter,
        /// Ask to remove the checked findings.
        RemoveSelected,
        /// Toggle the checkbox of the selected finding.
        ToggleCheck,
    ]
);

/// Key context of the category table; its bindings act only while it has focus.
pub const CATEGORY_TABLE_CONTEXT: &str = "CategoryTable";

/// Global application state shared by every view.
pub struct AppState {
    pub engine: Arc<Engine>,
}

impl Global for AppState {}

/// The main window's scan controller, reachable from app-level action handlers (the menu's
/// Rescan works with nothing focused).
struct MainScan(Entity<ScanController>);

impl Global for MainScan {}

/// Start a scan through the main window's controller, if there is one.
fn start_scan(cx: &mut App) {
    if let Some(scan) = cx.try_global::<MainScan>().map(|m| m.0.clone()) {
        scan.update(cx, |s, cx| s.start(cx));
    }
}

/// Which screen the content area shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    Overview,
    Category(Category),
    Settings,
}

impl Route {
    /// The screen's title, as shown in the title bar.
    pub fn title(&self) -> String {
        match self {
            Route::Overview => "Overview".to_string(),
            Route::Category(c) => c.to_string(),
            Route::Settings => "Settings".to_string(),
        }
    }
}

/// The main window's root view: title bar, sidebar and the current screen.
pub struct AppView {
    route: Route,
    sidebar_collapsed: bool,
    /// `Overview::by_category`, shown as sidebar weights.
    weights: Vec<(Category, u64)>,
    overview: Entity<OverviewView>,
    scan: Entity<ScanController>,
    focus: FocusHandle,
    _appearance: Subscription,
    _scan_events: Subscription,
}

impl AppView {
    /// Build the view; reads the category weights from the global [`AppState`].
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let appearance = cx.observe_window_appearance(window, |_, window, cx| {
            Theme::sync_system_appearance(Some(window), cx);
        });
        let weights = cx.global::<AppState>().engine.overview().by_category;
        let scan = cx.global::<MainScan>().0.clone();
        let scan_events = cx.subscribe_in(&scan, window, Self::on_scan_msg);
        let app = cx.weak_entity();
        let overview_scan = scan.clone();
        let overview = cx.new(|cx| OverviewView::new(app, overview_scan, cx));
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        AppView {
            route: Route::Overview,
            sidebar_collapsed: false,
            weights,
            overview,
            scan,
            focus,
            _appearance: appearance,
            _scan_events: scan_events,
        }
    }

    /// Fan a scan result out to the views: refresh on new data, a toast otherwise.
    fn on_scan_msg(
        &mut self,
        _: &Entity<ScanController>,
        msg: &ScanMsg,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match msg {
            // The Overview observes the controller for progress itself.
            ScanMsg::Progress(_) => {}
            ScanMsg::Finished(ScanStatus::Done { .. }) | ScanMsg::Refreshed => {
                self.refresh_data(cx)
            }
            ScanMsg::Finished(ScanStatus::Failed { error }) => {
                window.push_notification(Notification::error(error.clone()), cx);
            }
            ScanMsg::Finished(ScanStatus::Cancelled { .. }) => {
                window.push_notification(
                    Notification::info("Scan cancelled; previous data kept"),
                    cx,
                );
            }
            ScanMsg::Finished(ScanStatus::Running { .. } | ScanStatus::Unknown) => {}
            ScanMsg::SnapshotUpdatedElsewhere(_) => cx.notify(),
        }
    }

    /// Re-read the engine's snapshot everywhere it is shown: sidebar weights and Overview.
    fn refresh_data(&mut self, cx: &mut Context<Self>) {
        self.weights = cx.global::<AppState>().engine.overview().by_category;
        self.overview.update(cx, |o, cx| o.refresh(cx));
        // Task 9: refresh category views
        cx.notify();
    }

    /// "Snapshot updated by discky-mcp at <when> · Reload", above the route content.
    fn elsewhere_banner(&self, cx: &App) -> Option<impl IntoElement + use<>> {
        let meta = self.scan.read(cx).updated_elsewhere.clone()?;
        let by = match meta.actor {
            Actor::Mcp => "discky-mcp",
            Actor::App => "Discky.app",
        };
        let scan = self.scan.clone();
        let theme = cx.theme();
        Some(
            h_flex()
                .flex_shrink_0()
                .gap_2()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(theme.border)
                .bg(theme.primary.opacity(0.08))
                .text_sm()
                .child(div().flex_1().child(format!(
                    "Snapshot updated by {by} at {}",
                    format::when(meta.created_at)
                )))
                .child(
                    Button::new("reload-snapshot")
                        .small()
                        .label("Reload")
                        .on_click(move |_, _, cx| {
                            scan.update(cx, |s, cx| s.reload_from_disk(cx));
                        }),
                ),
        )
    }

    /// Show `r` in the content area. The Overview re-reads the snapshot when it is shown.
    pub fn navigate(&mut self, r: Route, cx: &mut Context<Self>) {
        if self.route != r {
            self.route = r;
            if r == Route::Overview {
                self.overview.update(cx, |o, cx| o.refresh(cx));
            }
            cx.notify();
        }
    }
}

impl Render for AppView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let title = self.route.title();
        let muted = cx.theme().muted_foreground;
        let content = match self.route {
            Route::Overview => self.overview.clone().into_any_element(),
            // Placeholders until the Category and Settings screens exist.
            Route::Category(_) | Route::Settings => v_flex()
                .flex_1()
                .h_full()
                .items_center()
                .justify_center()
                .text_color(muted)
                .child(title.clone())
                .into_any_element(),
        };
        v_flex()
            .id("app")
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &Rescan, _, cx| {
                this.scan.update(cx, |s, cx| s.start(cx));
            }))
            .on_action(
                cx.listener(|this, _: &OpenSettings, _, cx| this.navigate(Route::Settings, cx)),
            )
            .on_action(cx.listener(|this, _: &About, _, cx| {
                // The About page lives in Settings.
                this.navigate(Route::Settings, cx)
            }))
            .child(
                TitleBar::new().child(
                    h_flex()
                        .gap_2()
                        .text_sm()
                        .child(div().font_semibold().child("Discky"))
                        .child(div().text_color(muted).child(title.clone())),
                ),
            )
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .child(sidebar::sidebar(
                        self.route,
                        &self.weights,
                        self.sidebar_collapsed,
                        cx.weak_entity(),
                    ))
                    // The content pane fills what the title bar and sidebar leave and clips to
                    // it, so a scrolling screen sizes to that height, not to its content.
                    .child(
                        v_flex()
                            .flex_1()
                            .h_full()
                            .min_w_0()
                            .min_h_0()
                            .overflow_hidden()
                            .children(self.elsewhere_banner(cx))
                            .child(content),
                    ),
                // The inspector slot (Task 10) goes here, right of the content.
            )
    }
}

/// Run Discky.app. With `self_check`, quit one second after the window opened and print
/// `self-check ok`.
pub fn run(self_check: bool) {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx: &mut App| {
            gpui_kit::init(cx);
            install_actions(cx);
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();

            // Open the first window synchronously: opening it from a spawned task busy-loops
            // when launched through LaunchServices.
            let launch = if self_check {
                Launch::SelfCheck
            } else {
                Launch::Interactive
            };
            let options = EngineOptions::resolve(Actor::App);
            match Engine::open_with(options.clone()) {
                Ok(engine) => open_main_window(Arc::new(engine), launch, cx),
                Err(err) => open_startup_error(&err, options, launch, cx),
            }
            // Owner rule: automated runs never steal keyboard focus from the user's current
            // window. Only an interactive launch activates the app; `--self-check` keeps its
            // window hidden and unfocused (see `window_options`) and never activates.
            if launch == Launch::Interactive {
                cx.activate(true);
            }

            if self_check {
                cx.spawn(async move |cx| {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    let mut out = std::io::stdout();
                    let _ = writeln!(out, "self-check ok");
                    let _ = out.flush();
                    cx.update(|cx| cx.quit());
                })
                .detach();
            }
        });
}

/// Key bindings, app-level action handlers and the menu bar.
fn install_actions(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("cmd-r", Rescan, None),
        KeyBinding::new("cmd-,", OpenSettings, None),
        KeyBinding::new("cmd-q", Quit, None),
        KeyBinding::new("cmd-f", FocusFilter, Some(CATEGORY_TABLE_CONTEXT)),
        KeyBinding::new("space", ToggleCheck, Some(CATEGORY_TABLE_CONTEXT)),
        KeyBinding::new("backspace", RemoveSelected, Some(CATEGORY_TABLE_CONTEXT)),
    ]);
    cx.on_action(|_: &Quit, cx: &mut App| cx.quit());
    // Also handled on the main view's root; this one serves the menu with nothing focused.
    cx.on_action(|_: &Rescan, cx: &mut App| start_scan(cx));
    cx.set_menus([
        Menu::new("Discky").items([
            MenuItem::action("About Discky", About),
            MenuItem::separator(),
            MenuItem::action("Settings…", OpenSettings),
            MenuItem::separator(),
            MenuItem::action("Quit Discky", Quit),
        ]),
        Menu::new("File").items([MenuItem::action("Rescan", Rescan)]),
        Menu::new("Edit").items([
            MenuItem::action("Undo", input::Undo),
            MenuItem::action("Redo", input::Redo),
            MenuItem::separator(),
            MenuItem::action("Cut", input::Cut),
            MenuItem::action("Copy", input::Copy),
            MenuItem::action("Paste", input::Paste),
            MenuItem::action("Select All", input::SelectAll),
        ]),
        // AppKit fills a menu named "Window" with the standard window items.
        Menu::new("Window"),
    ]);
}

/// How Discky was started.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Launch {
    /// A normal run: windows are shown, focused and the app is activated.
    Interactive,
    /// `--self-check`: windows are created hidden and unfocused, so an automated run
    /// never takes keyboard focus from the user.
    SelfCheck,
}

/// Window options shared by Discky's windows: the kit's title bar, centered at `size`;
/// hidden and unfocused for [`Launch::SelfCheck`].
fn window_options(
    size: Size<Pixels>,
    min: Size<Pixels>,
    launch: Launch,
    cx: &App,
) -> WindowOptions {
    let interactive = launch == Launch::Interactive;
    WindowOptions {
        show: interactive,
        focus: interactive,
        titlebar: Some(TitlebarOptions {
            title: Some("Discky".into()),
            ..TitleBar::title_bar_options()
        }),
        window_bounds: Some(WindowBounds::centered(size, cx)),
        window_min_size: Some(min),
        ..TitleBar::window_options()
    }
}

/// Make `engine` the global state and open the main window.
fn open_main_window(engine: Arc<Engine>, launch: Launch, cx: &mut App) {
    cx.set_global(AppState { engine });
    let scan = cx.new(ScanController::new);
    cx.set_global(MainScan(scan));
    let options = window_options(
        size(px(1100.), px(720.)),
        size(px(800.), px(500.)),
        launch,
        cx,
    );
    let opened = gpui_kit::open_window(options, cx, |window, cx| {
        Theme::sync_system_appearance(Some(window), cx);
        cx.new(|cx| AppView::new(window, cx))
    });
    if let Err(e) = opened {
        eprintln!("Discky cannot open its window: {e}");
        cx.quit();
    }
}

/// `<config>.bak`, where "Reset to defaults" keeps the unreadable config.
fn backup_path(config: &Path) -> PathBuf {
    let mut s = config.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

/// The startup dialog's body for a config that cannot be loaded.
pub fn startup_error_text(err: &ConfigError, paths: &DisckyPaths) -> String {
    let config = display(&paths.config);
    let reason = match err {
        ConfigError::Parse { source, .. } => {
            format!(
                "`{config}` is not valid TOML:\n{}",
                source.to_string().trim_end()
            )
        }
        ConfigError::Io { source, .. } => format!("`{config}` cannot be read:\n{source}"),
        ConfigError::Serialize(e) => e.to_string(),
    };
    let backup = backup_path(&paths.config);
    let backup_name = backup
        .file_name()
        .map_or_else(|| display(&backup), |n| n.to_string_lossy().into_owned());
    format!("{reason}\n\nReset to defaults replaces the file (a copy is kept as {backup_name}).")
}

/// Move the config aside to `<config>.bak` (replacing an older backup) and write the
/// defaults in its place. A missing config just gets the defaults.
pub fn reset_config(paths: &DisckyPaths) -> Result<(), ConfigError> {
    match std::fs::rename(&paths.config, backup_path(&paths.config)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ConfigError::Io {
                path: paths.config.clone(),
                source,
            });
        }
    }
    Config::default().save(paths)
}

/// The window shown instead of the main window when the engine cannot start.
struct StartupErrorView {
    options: EngineOptions,
    launch: Launch,
    text: SharedString,
    /// Whether "Reset to defaults" applies (the config could not be loaded).
    can_reset: bool,
    _appearance: Subscription,
}

impl StartupErrorView {
    fn reset(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let reopened = reset_config(&self.options.paths)
            .map_err(EngineError::from)
            .and_then(|()| Engine::open_with(self.options.clone()));
        match reopened {
            Ok(engine) => {
                // Open the main window before closing this one, so closing the last window
                // does not quit the app.
                open_main_window(Arc::new(engine), self.launch, cx);
                window.remove_window();
            }
            Err(err) => {
                self.text = error_text(&err, &self.options.paths).into();
                window.refresh();
            }
        }
    }
}

impl Render for StartupErrorView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .child(TitleBar::new())
    }
}

/// Dialog body for any engine start failure.
fn error_text(err: &EngineError, paths: &DisckyPaths) -> String {
    match err {
        EngineError::Config(e) => startup_error_text(e, paths),
        other => other.to_string(),
    }
}

/// Open a window whose only content is the startup error dialog.
fn open_startup_error(err: &EngineError, options: EngineOptions, launch: Launch, cx: &mut App) {
    let text = error_text(err, &options.paths);
    let can_reset = matches!(err, EngineError::Config(_));
    let win_options = window_options(
        size(px(720.), px(480.)),
        size(px(560.), px(360.)),
        launch,
        cx,
    );
    let opened = gpui_kit::open_window(win_options, cx, |window, cx| {
        Theme::sync_system_appearance(Some(window), cx);
        cx.new(|cx| StartupErrorView {
            options,
            launch,
            text: text.into(),
            can_reset,
            _appearance: cx.observe_window_appearance(window, |_, window, cx| {
                Theme::sync_system_appearance(Some(window), cx);
            }),
        })
    });
    let (handle, view) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            eprintln!("Discky cannot open its window: {e}");
            cx.quit();
            return;
        }
    };
    let _ = handle.update(cx, |_, window, cx| {
        window.open_dialog(cx, move |dialog, _, cx| {
            let state = view.read(cx);
            let reset_view = view.clone();
            dialog
                .title("Discky cannot read its settings")
                .close_button(false)
                .overlay_closable(false)
                .keyboard(false)
                .child(
                    div()
                        .text_sm()
                        .whitespace_normal()
                        .child(state.text.clone()),
                )
                .footer(
                    h_flex()
                        .w_full()
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("quit")
                                .label("Quit")
                                .on_click(|_, _, cx| cx.quit()),
                        )
                        .when(state.can_reset, |this| {
                            this.child(
                                Button::new("reset")
                                    .primary()
                                    .label("Reset to defaults")
                                    .on_click(move |_, window, cx| {
                                        reset_view.update(cx, |v, cx| v.reset(window, cx));
                                    }),
                            )
                        }),
                )
        });
    });
}

#[cfg(test)]
mod tests {
    // Not `use super::*`: the GPUI glob brings a `test` attribute macro that shadows std's.
    use super::{reset_config, startup_error_text};
    use discky_core::{Config, DisckyPaths};
    use std::path::PathBuf;

    /// A fresh directory under the system temp dir, removed by the caller.
    fn temp_home(name: &str) -> (PathBuf, DisckyPaths) {
        let dir = std::env::temp_dir().join(format!("discky-app-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = DisckyPaths {
            config: dir.join("config.toml"),
            snapshot: dir.join("snapshot.bin"),
            log: dir.join("removals.log"),
        };
        (dir, paths)
    }

    #[test]
    fn startup_error_text_names_file() {
        let (dir, paths) = temp_home("text");
        std::fs::write(&paths.config, "scan = = 1\n").unwrap();
        let err = Config::load(&paths).unwrap_err();
        let text = startup_error_text(&err, &paths);
        let head = format!("`{}` is not valid TOML:\n", paths.config.display());
        assert!(text.starts_with(&head), "{text}");
        assert!(text.len() > head.len() + 1, "error detail missing: {text}");
        assert!(
            text.ends_with(
                "\n\nReset to defaults replaces the file (a copy is kept as config.toml.bak)."
            ),
            "{text}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reset_config_keeps_a_backup_and_writes_defaults() {
        let (dir, paths) = temp_home("reset");
        std::fs::write(&paths.config, "scan = = 1\n").unwrap();
        reset_config(&paths).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml.bak")).unwrap(),
            "scan = = 1\n"
        );
        assert!(Config::load(&paths).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reset_config_without_a_file_writes_defaults() {
        let (dir, paths) = temp_home("reset-missing");
        reset_config(&paths).unwrap();
        assert!(paths.config.exists());
        assert!(!dir.join("config.toml.bak").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
