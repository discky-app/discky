//! Discky core library: paths, configuration and disk-cleanup logic.

pub mod config;
pub mod findings;
pub mod fs;
pub mod index;
pub mod paths;
pub mod rules;

pub use config::{Config, ConfigError, RemovalMode};
pub use paths::DisckyPaths;
