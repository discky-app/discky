//! The Overview screen (mockup A): hero number, disk bar and category cards.

mod access_notice;
pub mod model;

#[cfg(debug_assertions)]
use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use discky_core::rules::Category;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, Sizable as _, StyledExt as _, h_flex,
    v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::access::{self, AccessNotice, FdaStatus};
use crate::app::{AppState, AppView, Rescan, Route};
use crate::duck::{DuckScene, logo_element};
use crate::format;
use crate::palette;
use crate::scan::{ScanController, ScanMsg};
use model::{BarSegment, CategoryCard, OverviewModel};

/// The Overview screen. It never changes the route itself: clicks go to
/// [`AppView::navigate`].
pub struct OverviewView {
    model: OverviewModel,
    app: WeakEntity<AppView>,
    /// Shown instead of the hero while it runs.
    scan: Entity<ScanController>,
    /// The duck scene of the current (or last) scan; replaced when a scan starts.
    scene: Entity<DuckScene>,
    /// `started_at` of the scan `scene` belongs to.
    scene_scan: Option<Instant>,
    _scan_changed: Subscription,
    _scan_events: Subscription,
    _scene_changed: Subscription,
    /// Full Disk Access as last probed; `None` until the first probe ends.
    fda: Option<FdaStatus>,
    /// Access was seen denied this session, so a grant now needs a relaunch.
    saw_denied: bool,
    /// The access banner was closed (until the next launch).
    banner_dismissed: bool,
    /// The window lost activation at least once, so its next activation is a return.
    window_was_inactive: bool,
    /// Debug builds: `DISCKY_FDA` values used instead of the probe, one per check.
    #[cfg(debug_assertions)]
    fda_override: VecDeque<FdaStatus>,
    _fda_task: Task<()>,
    _activation: Subscription,
}

impl OverviewView {
    /// Build the screen from the current snapshot; `app` receives navigation, `scan` is
    /// shown while it runs.
    pub fn new(
        app: WeakEntity<AppView>,
        scan: Entity<ScanController>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let scan_changed = cx.observe(&scan, |this, scan, cx| {
            let started = scan.read(cx).started_at;
            if started.is_some() && started != this.scene_scan {
                // A new scan starts hidden again, with fresh trip bookkeeping.
                this.scene_scan = started;
                this.set_scene(cx.new(|_| DuckScene::new()), cx);
            }
            cx.notify();
        });
        let scan_events = cx.subscribe(&scan, |this, _, msg: &ScanMsg, cx| {
            this.scene.update(cx, |s, cx| s.apply(msg, cx));
            if let ScanMsg::Finished(_) = msg {
                this.check_access(cx);
            }
        });
        // Coming back (from System Settings) re-probes, so a fresh grant offers the relaunch.
        // The window's first activation at launch is no return: `new` already probes.
        let activation = cx.observe_window_activation(window, |this, window, cx| {
            if !window.is_window_active() {
                this.window_was_inactive = true;
            } else if this.window_was_inactive {
                this.check_access(cx);
            }
        });
        let scene = cx.new(|_| DuckScene::new());
        let scene_changed = cx.observe(&scene, |_, _, cx| cx.notify());
        let mut view = OverviewView {
            model: current_model(cx),
            app,
            scene_scan: scan.read(cx).started_at,
            scan,
            scene,
            _scan_changed: scan_changed,
            _scan_events: scan_events,
            _scene_changed: scene_changed,
            fda: None,
            saw_denied: false,
            banner_dismissed: false,
            window_was_inactive: false,
            #[cfg(debug_assertions)]
            fda_override: fda_override(),
            _fda_task: Task::ready(()),
            _activation: activation,
        };
        view.check_access(cx);
        view
    }

    /// Probe Full Disk Access off the main thread; the last status stays shown meanwhile.
    fn check_access(&mut self, cx: &mut Context<Self>) {
        let forced = self.forced_fda();
        let home = discky_core::paths::home_dir().unwrap_or_default();
        let work =
            cx.background_spawn(async move { forced.unwrap_or_else(|| access::probe_fda(&home)) });
        self._fda_task = cx.spawn(async move |this, cx| {
            let status = work.await;
            let _ = this.update(cx, |this, cx| {
                this.saw_denied |= status == FdaStatus::Denied;
                this.fda = Some(status);
                cx.notify();
            });
        });
    }

    /// Debug builds: the next `DISCKY_FDA` value, the last one repeating.
    #[cfg(debug_assertions)]
    fn forced_fda(&mut self) -> Option<FdaStatus> {
        if self.fda_override.len() > 1 {
            self.fda_override.pop_front()
        } else {
            self.fda_override.front().copied()
        }
    }

    #[cfg(not(debug_assertions))]
    fn forced_fda(&mut self) -> Option<FdaStatus> {
        None
    }

    /// Show `scene` from now on and re-render when it changes.
    fn set_scene(&mut self, scene: Entity<DuckScene>, cx: &mut Context<Self>) {
        self._scene_changed = cx.observe(&scene, |_, _, cx| cx.notify());
        self.scene = scene;
    }

    /// Rebuild the model from the engine's current snapshot (route shown, scan finished).
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.model = current_model(cx);
        cx.notify();
    }

    /// A click handler that shows `cat`'s screen.
    fn go_to(&self, cat: Category) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
        let app = self.app.clone();
        move |_, _, cx| {
            // The app view is gone only while its window closes; nothing to show then.
            let _ = app.update(cx, |v, cx| v.navigate(Route::Category(cat), cx));
        }
    }

    fn toolbar(&self, cx: &App) -> impl IntoElement {
        let m = &self.model;
        let label = if m.scanned_line.is_some() {
            "Rescan"
        } else {
            "Scan now"
        };
        let running = self.scan.read(cx).is_running();
        h_flex()
            .w_full()
            .justify_between()
            .gap_4()
            .child(div().text_xl().font_semibold().child("Overview"))
            .child(
                h_flex()
                    .gap_3()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(m.volume_line.clone())
                    .when_some(m.scanned_line.clone(), |this, s| this.child(s))
                    .when_some(m.stale_line.clone(), |this, s| {
                        this.child(format!("{s} · Rescan?"))
                    })
                    .child(rescan_button("rescan", label).disabled(running)),
            )
    }

    fn hero(&self, cx: &App) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let m = &self.model;
        v_flex()
            .gap_1()
            .child(
                h_flex()
                    .items_baseline()
                    .gap_3()
                    .child(
                        div()
                            .text_3xl()
                            .font_bold()
                            .child(format::bytes(m.safe_to_free)),
                    )
                    .child(div().text_lg().child("can be freed safely")),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(muted)
                    .child("findings that regenerate on their own"),
            )
            .when(!m.exact_note.is_empty(), |this| {
                this.child(div().text_xs().text_color(muted).child(m.exact_note))
            })
            // Only a scan can find unreadable folders, so this never shows without one.
            .when(self.model.no_access > 0, |this| {
                let app = self.app.clone();
                this.child(
                    h_flex()
                        .gap_1()
                        .text_sm()
                        .text_color(muted)
                        .child(match self.model.no_access {
                            1 => "1 folder could not be read ·".to_string(),
                            n => format!("{n} folders could not be read ·"),
                        })
                        .child(
                            Button::new("disk-access")
                                .link()
                                .small()
                                .label("Settings → Disk access")
                                .on_click(move |_, _, cx| {
                                    let _ = app.update(cx, |v, cx| v.navigate(Route::Settings, cx));
                                }),
                        ),
                )
            })
    }

    /// The running scan (or its scene playing out): the duck scene once it shows,
    /// "Scanning… N files · X" before that, and "Cancel" while the scan runs.
    ///
    /// The scene is always in the tree here, even while hidden: its render advances it.
    fn scan_progress(&self, scene_visible: bool, cx: &App) -> impl IntoElement {
        let controller = self.scan.read(cx);
        let p = &controller.progress;
        let running = controller.is_running();
        let scan = self.scan.clone();
        v_flex().gap_3().child(self.scene.clone()).child(
            h_flex()
                .gap_3()
                .when(!scene_visible, |this| {
                    this.child(div().text_lg().child(format!(
                        "Scanning… {} files · {}",
                        format::count(p.files),
                        format::bytes(p.allocated)
                    )))
                })
                .when(running, |this| {
                    this.child(
                        Button::new("cancel-scan")
                            .small()
                            .label("Cancel")
                            .on_click(move |_, _, cx| scan.update(cx, |s, cx| s.cancel(cx))),
                    )
                }),
        )
    }

    fn disk_bar(&self, cx: &App) -> impl IntoElement {
        let theme = cx.theme();
        let segments = self.model.bar.iter().filter(|s| s.label != "Free");
        v_flex()
            .gap_2()
            .child(
                h_flex()
                    .w_full()
                    .h(px(14.))
                    .rounded(theme.radius)
                    .overflow_hidden()
                    .border_1()
                    .border_color(theme.border)
                    // Free space is the bar's own background.
                    .bg(theme.background)
                    .children(segments.map(|s| {
                        div()
                            .h_full()
                            .w(relative(s.fraction))
                            .bg(segment_color(s, cx))
                    })),
            )
            .child(h_flex().flex_wrap().gap_x_4().gap_y_1().text_xs().children(
                self.model.bar.iter().map(|s| {
                    h_flex()
                        .gap_1p5()
                        .child(
                            div()
                                .size(px(8.))
                                .rounded_full()
                                .border_1()
                                .border_color(theme.border)
                                .bg(segment_color(s, cx)),
                        )
                        .child(s.label.clone())
                        .child(
                            div()
                                .text_color(theme.muted_foreground)
                                .child(format::bytes(s.bytes)),
                        )
                }),
            ))
    }

    fn card(&self, ix: usize, card: &CategoryCard, cx: &App) -> impl IntoElement {
        let theme = cx.theme();
        let header = model::card_header(card);
        v_flex()
            .p_4()
            .gap_1()
            .rounded(theme.radius_lg)
            .border_1()
            .border_color(theme.border)
            .child(div().pb_1().text_sm().font_semibold().child(header))
            .children(card.top.iter().enumerate().map(|(row, f)| {
                h_flex()
                    .id(SharedString::from(format!("card-{ix}-row-{row}")))
                    .gap_2()
                    .px_1()
                    .py_0p5()
                    .rounded(theme.radius)
                    .text_sm()
                    .cursor_pointer()
                    .hover(|s| s.bg(theme.accent))
                    .on_click(self.go_to(card.category))
                    .child(div().flex_shrink_0().child(f.title.clone()))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_color(theme.muted_foreground)
                            .child(f.subtitle.clone().unwrap_or_default()),
                    )
                    .child(div().flex_shrink_0().child(format::bytes(f.allocated)))
            }))
            .when(card.more > 0, |this| {
                this.child(
                    h_flex().pt_1().child(
                        Button::new(SharedString::from(format!("card-{ix}-more")))
                            .link()
                            .small()
                            .label(format!("{} more →", card.more))
                            .on_click(self.go_to(card.category)),
                    ),
                )
            })
    }

    fn empty_state(&self) -> impl IntoElement {
        v_flex()
            .flex_1()
            .items_center()
            .justify_center()
            .gap_4()
            .py_16()
            .child(logo_element(128.))
            .child(div().text_xl().font_semibold().child("No scan yet"))
            .child(rescan_button("scan-now", "Scan now").primary())
    }
}

impl Render for OverviewView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let has_snapshot = self.model.scanned_line.is_some();
        let notice = access::notice(
            self.fda,
            has_snapshot,
            self.saw_denied,
            self.banner_dismissed,
        );
        let banner = (notice == AccessNotice::Banner).then(|| self.access_banner(cx));
        let theme = cx.theme();
        let running = self.scan.read(cx).is_running();
        let scene_visible = self.scene.read(cx).visible();
        // The scene plays out after the scan ends; the hero number appears when it is done.
        let busy = running || scene_visible;
        let cards = self
            .model
            .cards
            .iter()
            .enumerate()
            .map(|(ix, c)| self.card(ix, c, cx));
        div()
            .id("overview")
            .size_full()
            .overflow_y_scrollbar()
            .child(
                v_flex()
                    .p_6()
                    .gap_6()
                    .when(notice == AccessNotice::Relaunch, |this| {
                        this.child(self.relaunch_card(cx))
                    })
                    .when_some(self.model.last_error.clone(), |this, e| {
                        this.child(
                            h_flex()
                                .gap_2()
                                .px_3()
                                .py_2()
                                .rounded(theme.radius)
                                .border_1()
                                .border_color(theme.warning)
                                .bg(theme.warning.opacity(0.1))
                                .text_sm()
                                .child(Icon::new(IconName::TriangleAlert).text_color(theme.warning))
                                .child(div().flex_1().child(e)),
                        )
                    })
                    .children(banner)
                    .child(self.toolbar(cx))
                    .when(busy, |this| {
                        this.child(self.scan_progress(scene_visible, cx))
                    })
                    .when(has_snapshot, |this| {
                        this.when(!busy, |this| this.child(self.hero(cx)))
                            .child(self.disk_bar(cx))
                            .child(div().grid().grid_cols(2).gap_4().children(cards))
                    })
                    .when(!has_snapshot && !busy, |this| {
                        if notice == AccessNotice::Onboarding {
                            this.child(self.onboarding_card(cx))
                        } else {
                            this.child(self.empty_state())
                        }
                    }),
            )
    }
}

/// The model for the engine in [`AppState`], now.
fn current_model(cx: &App) -> OverviewModel {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    model::build(&cx.global::<AppState>().engine, now)
}

/// Debug builds: `DISCKY_FDA`, a comma list of `denied`, `granted` or `unknown`.
#[cfg(debug_assertions)]
fn fda_override() -> VecDeque<FdaStatus> {
    let Ok(list) = std::env::var("DISCKY_FDA") else {
        return VecDeque::new();
    };
    list.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .filter_map(|v| match v {
            "denied" => Some(FdaStatus::Denied),
            "granted" => Some(FdaStatus::Granted),
            "unknown" => Some(FdaStatus::Unknown),
            other => {
                eprintln!("DISCKY_FDA: unknown value `{other}`");
                None
            }
        })
        .collect()
}

/// A button that dispatches [`Rescan`].
fn rescan_button(id: &'static str, label: &'static str) -> Button {
    Button::new(id)
        .small()
        .label(label)
        .on_click(|_, window, cx| window.dispatch_action(Box::new(Rescan), cx))
}

/// The colour of a bar segment: `chart_1..chart_5` for the first five categories in
/// sidebar order, `chart_bullish` and `warning` for the last two, `muted` for "Other
/// scanned", the bar background for "Free".
fn segment_color(s: &BarSegment, cx: &App) -> Hsla {
    let t = cx.theme();
    match s.category {
        Some(c) => palette::category_color(c, cx),
        None if s.label == "Free" => t.background,
        None => t.muted,
    }
}
