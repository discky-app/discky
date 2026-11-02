//! Discky core library: paths, configuration and disk-cleanup logic.

pub mod config;
pub mod fs;
pub mod index;
pub mod paths;

pub use config::{Config, ConfigError, RemovalMode};
pub use paths::DisckyPaths;
