//! The Disk map screen: breadcrumbs and mode controls, the treemap canvas with a hover
//! tooltip, and the colour legend.

pub mod layout;
pub mod model;
pub mod paint;

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use discky_core::findings::Finding;
use discky_core::index::NodeId;
use gpui_kit::component::breadcrumb::{Breadcrumb, BreadcrumbItem};
use gpui_kit::component::tab::{Tab, TabBar};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, StyledExt as _, h_flex, v_flex};
use gpui_kit::*;

use crate::app::AppState;
use crate::format;
use model::{ColorMode, DEPTH_MAX, DEPTH_MIN, MapModel, Paint, Rect, Tile, WeightMode};
use paint::Colors;

gpui_kit::actions!(
    map,
    [
        /// Show the parent of the current folder.
        MapUp,
        /// Show one more level of nesting.
        MapDepthMore,
        /// Show one level of nesting less.
        MapDepthLess,
    ]
);

/// Key context of the map screen; its bindings act only while it has focus.
pub const MAP_CONTEXT: &str = "Map";
pub const TOOLTIP_W: f32 = 300.0;
pub const TOOLTIP_OFFSET: (f32, f32) = (14.0, 18.0);
const FOOTER: &str = "Click: details · Double-click: open";
const COLOR_MODES: [ColorMode; 3] = [ColorMode::Category, ColorMode::Age, ColorMode::Files];
const WEIGHT_MODES: [WeightMode; 2] = [WeightMode::OnDisk, WeightMode::Claimed];
const SWATCH: f32 = 9.0;

/// Tooltip origin inside `container` for a mouse at `at`: offset right/down, flipped left/up when it would overflow.
pub fn tooltip_origin(at: (f32, f32), tip: (f32, f32), container: (f32, f32)) -> (f32, f32) {
    let axis = |at: f32, tip: f32, container: f32, offset: f32| {
        let after = at + offset;
        let v = if after + tip > container {
            at - offset - tip
        } else {
            after
        };
        v.max(0.)
    };
    (
        axis(at.0, tip.0, container.0, TOOLTIP_OFFSET.0),
        axis(at.1, tip.1, container.1, TOOLTIP_OFFSET.1),
    )
}

/// What the map asks the app for.
#[derive(Debug, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "emitted once per click, like `CategoryEvent::Inspect`"
)]
pub enum MapEvent {
    /// Show the folder or file at this path (no finding of its own).
    InspectPath(PathBuf),
    /// Show this finding in the inspector.
    InspectFinding(Finding),
    /// Close the inspector.
    Close,
}

/// Everything the tile layout depends on; the paint closure lays out again only when it changes.
#[derive(Clone, Copy, PartialEq)]
struct LayoutKey {
    root: Option<NodeId>,
    depth: u8,
    weight: WeightMode,
    /// Tiles carry their fill, so the colour mode is part of the key too.
    color: ColorMode,
    exclusions_version: u64,
    size: Size<Pixels>,
}

pub struct MapView {
    /// `None` until a snapshot exists ("Scan first").
    model: Option<MapModel>,
    /// The tiles last laid out by the canvas, in canvas coordinates, and their key.
    tiles: Rc<RefCell<Vec<Tile>>>,
    layout_key: Rc<Cell<Option<LayoutKey>>>,
    /// The canvas's window-relative bounds from its last prepaint.
    canvas_bounds: Rc<Cell<Bounds<Pixels>>>,
    /// Index into `tiles` under the mouse, and the mouse in canvas coordinates.
    hover: Option<usize>,
    hover_at: Option<Point<Pixels>>,
    /// Bumped by `exclude` and `reload`: both change the tiles without moving the root.
    exclusions_version: u64,
    focus: FocusHandle,
    /// Move keyboard focus here on the next render (the screen was just shown).
    focus_on_render: bool,
}

impl EventEmitter<MapEvent> for MapView {}

impl MapView {
    /// Built from the engine's snapshot; without one the screen reads "Scan first".
    pub fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut view = MapView {
            model: None,
            tiles: Rc::default(),
            layout_key: Rc::default(),
            canvas_bounds: Rc::default(),
            hover: None,
            hover_at: None,
            exclusions_version: 0,
            focus: cx.focus_handle(),
            focus_on_render: true,
        };
        view.load(cx);
        view
    }

    /// Takes the engine's current snapshot, keeping the folder shown when it still exists.
    pub fn reload(&mut self, cx: &mut Context<Self>) {
        self.load(cx);
        self.changed(cx);
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        let Some(snap) = cx.global::<AppState>().engine.snapshot() else {
            return;
        };
        match &mut self.model {
            Some(model) => model.set_snapshot(snap),
            None => {
                let home = discky_core::paths::home_dir().unwrap_or_default();
                self.model = Some(MapModel::new(snap, home, unix_now()));
            }
        }
        self.exclusions_version += 1;
    }

    /// Hides `paths` (just removed) until the next snapshot.
    pub fn exclude(&mut self, paths: &[PathBuf], cx: &mut Context<Self>) {
        if let Some(model) = &mut self.model {
            model.exclude(paths);
            self.exclusions_version += 1;
            self.changed(cx);
        }
    }

    /// Ask for keyboard focus when the screen is next drawn.
    pub fn request_focus(&mut self, cx: &mut Context<Self>) {
        self.focus_on_render = true;
        cx.notify();
    }

    /// The tiles are about to change: drop the hover and redraw.
    fn changed(&mut self, cx: &mut Context<Self>) {
        self.hover = None;
        self.hover_at = None;
        cx.notify();
    }

    /// Applies `f` to the model; redraws when it reports a change.
    fn update_model(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut MapModel) -> bool) {
        if let Some(model) = &mut self.model
            && f(model)
        {
            self.changed(cx);
        }
    }

    fn go_to(&mut self, node: Option<NodeId>, cx: &mut Context<Self>) {
        self.update_model(cx, |m| {
            let before = m.root();
            m.go_to(node);
            m.root() != before
        });
    }

    fn step_depth(&mut self, by: i8, cx: &mut Context<Self>) {
        self.update_model(cx, |m| m.set_depth(m.depth().saturating_add_signed(by)));
    }

    /// The tile under a window-relative `position`, and that point in canvas coordinates.
    fn hit(&self, position: Point<Pixels>) -> (Option<usize>, Point<Pixels>) {
        let at = position - self.canvas_bounds.get().origin;
        let hit = MapModel::tile_at(&self.tiles.borrow(), f32::from(at.x), f32::from(at.y));
        (hit, at)
    }

    fn on_mouse_move(&mut self, e: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        let (hit, at) = self.hit(e.position);
        let at = hit.map(|_| at);
        if hit != self.hover || at != self.hover_at {
            self.hover = hit;
            self.hover_at = at;
            cx.notify();
        }
    }

    fn on_hover(&mut self, hovered: &bool, _: &mut Window, cx: &mut Context<Self>) {
        if !*hovered && self.hover.is_some() {
            self.changed(cx);
        }
    }

    /// A double click opens a folder; a click asks for the tile's finding, or its path,
    /// to be inspected. Rest tiles do nothing.
    fn on_click(&mut self, e: &ClickEvent, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus, cx);
        let Some(position) = e.mouse_position() else {
            return;
        };
        let (Some(i), _) = self.hit(position) else {
            return;
        };
        let (node, is_dir) = {
            let tiles = self.tiles.borrow();
            (tiles[i].node, tiles[i].is_dir)
        };
        let (Some(node), Some(model)) = (node, &mut self.model) else {
            return;
        };
        if e.click_count() >= 2 {
            if is_dir && model.enter(node) {
                self.changed(cx);
            }
            return;
        }
        let snap = model.snapshot();
        let event = match model.direct_finding_index(node) {
            Some(f) => MapEvent::InspectFinding(snap.findings[f].clone()),
            None => MapEvent::InspectPath(snap.index.path(node)),
        };
        cx.emit(event);
    }

    fn toolbar(&self, model: &MapModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let muted = cx.theme().muted_foreground;
        let (weight, files) = model.totals();
        let crumbs: Vec<BreadcrumbItem> = model
            .crumbs()
            .into_iter()
            .map(|c| {
                let node = c.node;
                BreadcrumbItem::new(c.label)
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| this.go_to(node, cx)))
            })
            .collect();
        let color_ix = COLOR_MODES.iter().position(|&m| m == model.color());
        let weight_ix = WEIGHT_MODES.iter().position(|&m| m == model.weight_mode());
        h_flex()
            .flex_shrink_0()
            .gap_3()
            .px_4()
            .py_3()
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .gap_2()
                    .child(Breadcrumb::new().children(crumbs))
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_sm()
                            .text_color(muted)
                            .child(format!(
                                "· {} · {} files",
                                format::bytes(weight),
                                format::count(u64::from(files))
                            )),
                    ),
            )
            .child(
                TabBar::new("map-color")
                    .segmented()
                    .small()
                    .selected_index(color_ix.unwrap_or(0))
                    .children(COLOR_MODES.iter().map(|m| Tab::new().label(m.label())))
                    .on_click(cx.listener(|this, ix: &usize, _, cx| {
                        if let Some(&mode) = COLOR_MODES.get(*ix) {
                            this.update_model(cx, |m| m.set_color(mode));
                        }
                    })),
            )
            .child(
                TabBar::new("map-weight")
                    .segmented()
                    .small()
                    .selected_index(weight_ix.unwrap_or(0))
                    .children(WEIGHT_MODES.iter().map(|m| Tab::new().label(m.label())))
                    .on_click(cx.listener(|this, ix: &usize, _, cx| {
                        if let Some(&mode) = WEIGHT_MODES.get(*ix) {
                            this.update_model(cx, |m| m.set_weight_mode(mode));
                        }
                    })),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(div().text_sm().text_color(muted).child("Depth"))
                    .child(
                        TabBar::new("map-depth")
                            .segmented()
                            .small()
                            .selected_index(usize::from(model.depth() - DEPTH_MIN))
                            .children(
                                (DEPTH_MIN..=DEPTH_MAX).map(|d| Tab::new().label(d.to_string())),
                            )
                            .on_click(cx.listener(|this, ix: &usize, _, cx| {
                                let d = u8::try_from(*ix).map_or(DEPTH_MAX, |i| DEPTH_MIN + i);
                                this.update_model(cx, |m| m.set_depth(d));
                            })),
                    ),
            )
    }

    /// The canvas, its mouse handling, and the tooltip of the tile under the mouse.
    fn canvas_area(&self, model: &MapModel, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let colors = Colors::new(cx);
        let base = (
            model.root(),
            model.depth(),
            model.weight_mode(),
            model.color(),
            self.exclusions_version,
        );
        let (tiles, key_cell, bounds_cell) = (
            self.tiles.clone(),
            self.layout_key.clone(),
            self.canvas_bounds.clone(),
        );
        let view = cx.weak_entity();
        let hover = self.hover;
        let map = canvas(
            move |bounds, _, _| bounds_cell.set(bounds),
            move |bounds, (), window, cx| {
                let (root, depth, weight, color, exclusions_version) = base;
                let key = LayoutKey {
                    root,
                    depth,
                    weight,
                    color,
                    exclusions_version,
                    size: bounds.size,
                };
                let mut hover = hover;
                if key_cell.get() != Some(key)
                    && let Some(view) = view.upgrade()
                    && let Some(model) = &view.read(cx).model
                {
                    let rect = Rect {
                        x: 0.,
                        y: 0.,
                        w: f32::from(bounds.size.width),
                        h: f32::from(bounds.size.height),
                    };
                    *tiles.borrow_mut() = model.layout(rect);
                    key_cell.set(Some(key));
                    // The hovered index belonged to the previous tiles.
                    hover = None;
                }
                paint::paint_tiles(&tiles.borrow(), bounds, hover, &colors, window, cx);
            },
        )
        .size_full();
        div()
            .id("map-canvas")
            .relative()
            .flex_1()
            .min_h_0()
            .mx_4()
            .overflow_hidden()
            .cursor_default()
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .on_hover(cx.listener(Self::on_hover))
            .on_click(cx.listener(Self::on_click))
            .child(map)
            .children(self.tooltip(model, cx))
    }

    fn tooltip(&self, model: &MapModel, cx: &App) -> Option<impl IntoElement + use<>> {
        let (i, at) = (self.hover?, self.hover_at?);
        let tiles = self.tiles.borrow();
        let tile = tiles.get(i)?;
        let (title, rows) = model.tooltip(tile);
        let theme = cx.theme();
        let muted = theme.muted_foreground;
        // A Rest tile does nothing on click, so it gets no hint.
        let footer = tile.node.is_some().then(|| {
            div()
                .pt_1()
                .mt_1()
                .border_t_1()
                .border_color(theme.border)
                .text_color(muted)
                .child(FOOTER)
        });
        // Estimated height, used only to decide whether to flip upwards.
        let tip_h = 16. + 20. + 18. * rows.len() as f32 + if footer.is_some() { 26. } else { 0. };
        let container = self.canvas_bounds.get().size;
        let (x, y) = tooltip_origin(
            (f32::from(at.x), f32::from(at.y)),
            (TOOLTIP_W, tip_h),
            (f32::from(container.width), f32::from(container.height)),
        );
        Some(
            v_flex()
                .absolute()
                .left(px(x))
                .top(px(y))
                .w(px(TOOLTIP_W))
                .p_2()
                .gap_0p5()
                .bg(theme.popover)
                .text_color(theme.popover_foreground)
                .border_1()
                .border_color(theme.border)
                .rounded(theme.radius)
                .shadow_lg()
                .text_xs()
                .child(div().text_sm().font_semibold().truncate().child(title))
                .children(rows.into_iter().map(|(name, value)| {
                    h_flex()
                        .gap_2()
                        .child(
                            div()
                                .w(px(64.))
                                .flex_shrink_0()
                                .text_color(muted)
                                .child(name),
                        )
                        .child(div().flex_1().min_w_0().truncate().child(value))
                }))
                .children(footer),
        )
    }

    fn legend(model: &MapModel, colors: &Colors) -> impl IntoElement + use<> {
        h_flex()
            .flex_shrink_0()
            .flex_wrap()
            .gap_x_3()
            .gap_y_1()
            .px_4()
            .py_2()
            .text_xs()
            .text_color(colors.muted_foreground)
            .children(model.legend().into_iter().map(|(paint, label)| {
                let swatch = div()
                    .size(px(SWATCH))
                    .flex_shrink_0()
                    .bg(colors.fill(paint));
                let swatch = if paint == Paint::Cloud {
                    swatch.border_1().border_color(colors.muted_foreground)
                } else {
                    swatch
                };
                h_flex().gap_1p5().child(swatch).child(label)
            }))
    }
}

impl Render for MapView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if std::mem::take(&mut self.focus_on_render) {
            window.focus(&self.focus, cx);
        }
        let root = v_flex()
            .id("map")
            .key_context(MAP_CONTEXT)
            .track_focus(&self.focus)
            .size_full()
            .on_action(cx.listener(|this, _: &MapUp, _, cx| this.update_model(cx, MapModel::up)))
            .on_action(cx.listener(|this, _: &MapDepthMore, _, cx| this.step_depth(1, cx)))
            .on_action(cx.listener(|this, _: &MapDepthLess, _, cx| this.step_depth(-1, cx)));
        let Some(model) = &self.model else {
            return root
                .items_center()
                .justify_center()
                .text_color(cx.theme().muted_foreground)
                .child("Scan first");
        };
        let colors = Colors::new(cx);
        root.child(self.toolbar(model, cx))
            .child(self.canvas_area(model, cx))
            .child(Self::legend(model, &colors))
    }
}

/// The current time in Unix seconds (0 if the clock is before 1970).
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    // Not `use super::*`: the GPUI glob brings a `test` attribute macro that shadows std's.
    use super::tooltip_origin;

    #[test]
    fn tooltip_flips_near_the_right_and_bottom_edges() {
        let (tip, container) = ((300., 120.), (800., 600.));
        assert_eq!(tooltip_origin((10., 10.), tip, container), (24., 28.));
        assert_eq!(
            tooltip_origin((700., 550.), tip, container),
            (700. - 14. - 300., 550. - 18. - 120.)
        );
        // Only the overflowing axis flips.
        assert_eq!(tooltip_origin((700., 10.), tip, container), (386., 28.));
        assert_eq!(tooltip_origin((10., 550.), tip, container), (24., 412.));
        // Never above or left of the container.
        assert_eq!(tooltip_origin((100., 100.), tip, (200., 150.)), (0., 0.));
    }
}
