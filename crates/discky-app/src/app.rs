//! Application state, routes, actions and menus; the main window shell and the startup
//! error window.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use discky_core::findings::Finding;
use discky_core::history;
use discky_core::index::snapshot::Actor;
use discky_core::paths::display;
use discky_core::rules::Category;
use discky_core::{
    Config, ConfigError, DisckyPaths, Engine, EngineError, EngineOptions, PlanItem, ScanStatus,
};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input;
use gpui_kit::component::notification::Notification;
use gpui_kit::component::{
    ActiveTheme as _, Sizable as _, StyledExt as _, Theme, TitleBar, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::category::{CategoryEvent, CategoryView};
use crate::format;
use crate::inspector::{INSPECTOR_CONTEXT, Inspector, InspectorEvent};
use crate::overview::OverviewView;
use crate::removal::model::{BUSY_MESSAGE, REMOVAL_BUSY_MESSAGE, RunFlag, SCAN_BLOCKED_MESSAGE};
use crate::removal::{self, RemovalDialog, RemovalEvent};
use crate::scan::{ScanController, ScanMsg};
use crate::settings::{Section, SettingsView};
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
        /// Close the inspector.
        CloseInspector,
    ]
);

/// Key context of the category table; its bindings act only while it has focus.
pub const CATEGORY_TABLE_CONTEXT: &str = "CategoryTable";

/// Global application state shared by every view.
pub struct AppState {
    pub engine: Arc<Engine>,
    /// Set while a removal plan executes; closing the window, quitting, scanning and a
    /// second removal wait for it.
    pub removal_running: RunFlag,
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
    /// `Overview::apps_unused`, shown next to Applications.
    apps_unused: usize,
    overview: Entity<OverviewView>,
    settings: Entity<SettingsView>,
    /// One screen per category visited so far, created on first visit.
    categories: HashMap<Category, Entity<CategoryView>>,
    /// The right column showing the finding last selected in a category table.
    inspector: Option<Entity<Inspector>>,
    /// The removal dialog opened last, kept so its run finishes and reports back even
    /// after the dialog was closed.
    removal: Option<Entity<RemovalDialog>>,
    scan: Entity<ScanController>,
    focus: FocusHandle,
    _appearance: Subscription,
    _scan_events: Subscription,
    _category_events: Vec<Subscription>,
    _inspector_events: Option<Subscription>,
    _removal_events: Option<Subscription>,
}

impl AppView {
    /// Build the view; reads the category weights from the global [`AppState`].
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let appearance = cx.observe_window_appearance(window, |_, window, cx| {
            Theme::sync_system_appearance(Some(window), cx);
        });
        let overview_data = cx.global::<AppState>().engine.overview();
        let (weights, apps_unused) = (overview_data.by_category, overview_data.apps_unused);
        let scan = cx.global::<MainScan>().0.clone();
        let scan_events = cx.subscribe_in(&scan, window, Self::on_scan_msg);
        let app = cx.weak_entity();
        let overview_scan = scan.clone();
        let settings_app = app.clone();
        let overview = cx.new(|cx| OverviewView::new(app, overview_scan, cx));
        let settings =
            cx.new(|cx| SettingsView::new(start_settings_section(), settings_app, window, cx));
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        let mut view = AppView {
            route: start_route(),
            sidebar_collapsed: false,
            weights,
            apps_unused,
            overview,
            settings,
            categories: HashMap::new(),
            inspector: None,
            removal: None,
            scan,
            focus,
            _appearance: appearance,
            _scan_events: scan_events,
            _category_events: Vec::new(),
            _inspector_events: None,
            _removal_events: None,
        };
        view.start_inspect(window, cx);
        // The dialog layer exists only once the window's root wraps this view.
        cx.defer_in(window, Self::start_remove);
        view
    }

    /// In debug builds, open the inspector on the finding named by `DISCKY_START_INSPECT`
    /// (an id, absolute path or title, as `Engine::inspect` resolves it), so the panel can
    /// be looked at without clicking a row.
    fn start_inspect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        #[cfg(debug_assertions)]
        if let Ok(target) = std::env::var("DISCKY_START_INSPECT") {
            let found = cx
                .global::<AppState>()
                .engine
                .inspect(&target)
                .and_then(|i| i.finding);
            match found {
                Some(f) => self.inspect(f, window, cx),
                None => eprintln!("DISCKY_START_INSPECT: no finding `{target}`"),
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = (window, cx);
    }

    /// In debug builds, open the removal dialog for the comma-separated findings in
    /// `DISCKY_START_REMOVE` (ids, absolute paths or titles, resolved like
    /// `DISCKY_START_INSPECT`; an unresolved token is passed on as an id), so the dialog can be looked at without clicking. It only
    /// plans; nothing runs until Run is pressed.
    fn start_remove(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        #[cfg(debug_assertions)]
        if let Ok(list) = std::env::var("DISCKY_START_REMOVE") {
            let engine = cx.global::<AppState>().engine.clone();
            let ids: Vec<String> = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|t| match engine.inspect(t).and_then(|i| i.finding) {
                    Some(f) => f.id.0,
                    None => t.to_string(),
                })
                .collect();
            if !ids.is_empty() {
                self.open_removal(defaults(ids), window, cx);
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = (window, cx);
    }

    /// Open the removal dialog for `items` (it plans them afresh); refused while a removal
    /// runs, so one run's dialog and flag are never replaced by another's.
    fn open_removal(&mut self, items: Vec<PlanItem>, window: &mut Window, cx: &mut Context<Self>) {
        if removal_running(cx) {
            window.push_notification(Notification::warning(REMOVAL_BUSY_MESSAGE), cx);
            return;
        }
        let dialog = removal::open(items, window, cx);
        self._removal_events = Some(cx.subscribe(&dialog, Self::on_removal_event));
        self.removal = Some(dialog);
    }

    /// A removal run ended: close the inspector when its finding is gone, then re-read
    /// the snapshot everywhere, as after a scan.
    fn on_removal_event(
        &mut self,
        _: Entity<RemovalDialog>,
        event: &RemovalEvent,
        cx: &mut Context<Self>,
    ) {
        match event {
            RemovalEvent::Ran => {
                if let Some(inspector) = &self.inspector {
                    let id = inspector.read(cx).finding_id().0.clone();
                    let present = cx
                        .global::<AppState>()
                        .engine
                        .snapshot()
                        .is_some_and(|s| s.findings.iter().any(|f| f.id.0 == id));
                    if !present {
                        self.close_inspector(cx);
                    }
                }
                self.refresh_data(cx);
            }
        }
    }

    /// Show `f` in the inspector, opening it if needed. Nothing happens when it already
    /// shows `f`: the table re-selects the same row after every reload or filter keystroke,
    /// and the inspector keeps its state (and its plan) for it.
    fn inspect(&mut self, f: Finding, window: &mut Window, cx: &mut Context<Self>) {
        match &self.inspector {
            Some(inspector) => {
                if inspector.read(cx).finding_id() != &f.id {
                    inspector.update(cx, |i, cx| i.set_finding(f, cx));
                }
            }
            None => {
                let inspector = cx.new(|cx| Inspector::new(f, cx));
                self._inspector_events =
                    Some(cx.subscribe_in(&inspector, window, Self::on_inspector_event));
                self.inspector = Some(inspector);
                cx.notify();
            }
        }
    }

    /// Close the inspector; keyboard focus goes back to the category table.
    fn close_inspector(&mut self, cx: &mut Context<Self>) {
        if self.inspector.take().is_none() {
            return;
        }
        self._inspector_events = None;
        if let Route::Category(c) = self.route
            && let Some(view) = self.categories.get(&c)
        {
            view.update(cx, |v, cx| v.request_focus(cx));
        }
        cx.notify();
    }

    fn on_inspector_event(
        &mut self,
        _: &Entity<Inspector>,
        event: &InspectorEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            InspectorEvent::Close => self.close_inspector(cx),
            InspectorEvent::RemoveItems(items) => {
                self.open_removal(items.clone(), window, cx);
            }
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
            // The engine publishes the new snapshot in memory even when saving it failed.
            ScanMsg::Finished(ScanStatus::Failed { error }) => {
                self.refresh_data(cx);
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
            ScanMsg::RefusedDuringRemoval => {
                window.push_notification(Notification::warning(SCAN_BLOCKED_MESSAGE), cx);
            }
        }
    }

    /// Re-read the engine's snapshot everywhere it is shown: sidebar weights, Overview
    /// and every category screen created so far.
    fn refresh_data(&mut self, cx: &mut Context<Self>) {
        let overview = cx.global::<AppState>().engine.overview();
        self.weights = overview.by_category;
        self.apps_unused = overview.apps_unused;
        self.overview.update(cx, |o, cx| o.refresh(cx));
        for view in self.categories.values() {
            view.update(cx, |v, cx| v.reload(cx));
        }
        if let Some(inspector) = &self.inspector {
            inspector.update(cx, |i, cx| i.refresh(cx));
        }
        cx.notify();
    }

    /// The screen of `category`, created (and subscribed to) on first use.
    fn category_view(
        &mut self,
        category: Category,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<CategoryView> {
        if let Some(view) = self.categories.get(&category) {
            return view.clone();
        }
        let view = cx.new(|cx| CategoryView::new(category, window, cx));
        self._category_events
            .push(cx.subscribe_in(&view, window, Self::on_category_event));
        self.categories.insert(category, view.clone());
        view
    }

    /// Route a category screen's request: inspector or removal.
    fn on_category_event(
        &mut self,
        _: &Entity<CategoryView>,
        event: &CategoryEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            CategoryEvent::Inspect(finding) => self.inspect(finding.clone(), window, cx),
            CategoryEvent::Cleared => self.close_inspector(cx),
            CategoryEvent::RemoveRequested(ids) => {
                self.open_removal(defaults(ids.clone()), window, cx);
            }
        }
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

    /// Show `r` in the content area. The Overview re-reads the snapshot when it is shown;
    /// the inspector closes on any route change.
    pub fn navigate(&mut self, r: Route, cx: &mut Context<Self>) {
        if self.route != r {
            self.close_inspector(cx);
            self.route = r;
            match r {
                Route::Overview => self.overview.update(cx, |o, cx| o.refresh(cx)),
                Route::Category(c) => {
                    if let Some(view) = self.categories.get(&c) {
                        view.update(cx, |v, cx| v.request_focus(cx));
                    }
                }
                Route::Settings => self.settings.update(cx, |s, cx| s.on_shown(cx)),
            }
            cx.notify();
        }
    }

    /// Show Settings at `section` (⌘, and the menu open Removal; About opens About).
    pub fn open_settings(&mut self, section: Section, cx: &mut Context<Self>) {
        self.settings.update(cx, |s, cx| s.set_section(section, cx));
        self.navigate(Route::Settings, cx);
    }
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let title = self.route.title();
        let muted = cx.theme().muted_foreground;
        let content = match self.route {
            Route::Overview => self.overview.clone().into_any_element(),
            Route::Category(c) => self.category_view(c, window, cx).into_any_element(),
            Route::Settings => self.settings.clone().into_any_element(),
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
                cx.listener(|this, _: &OpenSettings, _, cx| {
                    this.open_settings(Section::Removal, cx)
                }),
            )
            .on_action(cx.listener(|this, _: &About, _, cx| this.open_settings(Section::About, cx)))
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
                        self.apps_unused,
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
                    )
                    .children(self.inspector.clone().map(|inspector| {
                        div()
                            .flex_shrink_0()
                            .w(px(400.))
                            .h_full()
                            .min_h_0()
                            .border_l_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().background)
                            .child(inspector)
                    })),
            )
    }
}

/// The first screen: the Overview, or in debug builds the route named by
/// `DISCKY_START_ROUTE` (`overview`, `settings` or a category such as `app_caches`), so a
/// screen can be looked at without clicking to it.
fn start_route() -> Route {
    #[cfg(debug_assertions)]
    if let Ok(name) = std::env::var("DISCKY_START_ROUTE") {
        match name.as_str() {
            "overview" => return Route::Overview,
            "settings" => return Route::Settings,
            other => {
                match serde_json::from_value::<Category>(serde_json::Value::String(other.into())) {
                    Ok(c) => return Route::Category(c),
                    Err(_) => eprintln!("DISCKY_START_ROUTE: unknown route `{other}`"),
                }
            }
        }
    }
    Route::Overview
}

/// The Settings page shown first: Removal, or in debug builds the section named by
/// `DISCKY_START_SETTINGS` (`scanning`, `removal`, `version_manager`, `mcp`, `disk_access`,
/// `about`), so a page can be looked at without clicking to it.
fn start_settings_section() -> Section {
    #[cfg(debug_assertions)]
    if let Ok(name) = std::env::var("DISCKY_START_SETTINGS") {
        match Section::parse(&name) {
            Some(s) => return s,
            None => eprintln!("DISCKY_START_SETTINGS: unknown section `{name}`"),
        }
    }
    Section::Removal
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
            // ⌘Q and the menu refuse while a removal runs, but the Dock's Quit, logout and
            // restart cannot be refused through gpui: log the step they cut off.
            cx.on_app_quit(|cx| {
                record_interrupted_step(cx);
                async {}
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
        KeyBinding::new("escape", CloseInspector, Some(INSPECTOR_CONTEXT)),
    ]);
    cx.on_action(|_: &Quit, cx: &mut App| quit(cx));
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

/// Plan requests for `ids` with their default components (the table's checkboxes).
fn defaults(ids: Vec<String>) -> Vec<PlanItem> {
    ids.into_iter()
        .map(|id| PlanItem {
            id,
            components: None,
            parts: None,
        })
        .collect()
}

/// Whether a removal plan is executing right now.
fn removal_running(cx: &App) -> bool {
    cx.try_global::<AppState>()
        .is_some_and(|s| s.removal_running.is_running())
}

/// The app is quitting: if a removal step is running, append an `interrupted` record for
/// it to the removal log (written right here; quit handlers get only ~200 ms).
fn record_interrupted_step(cx: &App) {
    let Some(state) = cx.try_global::<AppState>() else {
        return;
    };
    if let Some((plan, step)) = state.removal_running.interrupted() {
        let paths = state.engine.paths();
        if let Err(e) = history::append_interrupted(paths, &plan, &step, Actor::App) {
            eprintln!("Cannot log the interrupted removal step: {e}");
        }
    }
}

/// Quit, unless a removal is running: then say so in the active window and stay, so a
/// step (a permanent delete, a cross-volume move, a tool) is never cut off part-way.
fn quit(cx: &mut App) {
    if !removal_running(cx) {
        cx.quit();
        return;
    }
    if let Some(window) = cx.active_window().or_else(|| cx.windows().first().copied()) {
        let _ = window.update(cx, |_, window, cx| {
            window.push_notification(Notification::warning(BUSY_MESSAGE), cx);
        });
    }
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
    cx.set_global(AppState {
        engine,
        removal_running: RunFlag::default(),
    });
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
    match opened {
        // Closing the window quits the app; refuse while a removal is running.
        Ok((handle, _)) => {
            let _ = handle.update(cx, |_, window, cx| {
                window.on_window_should_close(cx, |window, cx| {
                    if removal_running(cx) {
                        window.push_notification(Notification::warning(BUSY_MESSAGE), cx);
                        return false;
                    }
                    true
                });
            });
        }
        Err(e) => {
            eprintln!("Discky cannot open its window: {e}");
            cx.quit();
        }
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
