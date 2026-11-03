//! Discky.app: the GUI shell over `discky-core`.

pub mod app;
pub mod category;
pub mod duck;
pub mod format;
pub mod inspector;
pub mod overview;
pub mod removal;
pub mod scan;
pub mod settings;
pub mod sidebar;

pub use app::run;
