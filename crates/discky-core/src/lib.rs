//! Discky core library: paths, configuration and disk-cleanup logic.

pub mod config;
pub mod engine;
pub mod findings;
pub mod fs;
pub mod history;
pub mod index;
pub mod paths;
pub mod plan;
pub mod query;
pub mod rules;
pub mod scan;
pub mod tools;

pub use config::{Config, ConfigError, RemovalMode};
pub use engine::{Engine, EngineError, Inspection};
pub use paths::DisckyPaths;
pub use scan::{ScanId, ScanStatus};
