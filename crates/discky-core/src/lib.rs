//! Discky core library: paths, configuration and disk-cleanup logic.

pub mod config;
pub mod findings;
pub mod fs;
pub mod history;
pub mod index;
pub mod paths;
pub mod plan;
pub mod query;
pub mod rules;
pub mod tools;

pub use config::{Config, ConfigError, RemovalMode};
pub use paths::DisckyPaths;
