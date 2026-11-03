use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::DisckyPaths;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("cannot serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemovalMode {
    Trash,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            roots: [
                "~",
                "/Applications",
                "/Library",
                "/usr/local",
                "/opt/homebrew",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            exclude: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemovalConfig {
    pub mode: RemovalMode,
    pub remind_trash: bool,
}

impl Default for RemovalConfig {
    fn default() -> Self {
        RemovalConfig {
            mode: RemovalMode::Trash,
            remind_trash: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub large_file_bytes: u64,
    pub old_days: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            large_file_bytes: 524_288_000,
            old_days: 365,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    pub allow_agent_delete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub scan: ScanConfig,
    pub removal: RemovalConfig,
    pub thresholds: Thresholds,
    pub mcp: McpConfig,
}

impl Config {
    /// Load the config; a missing file yields defaults. A leading `~` in
    /// `scan.roots` entries (the defaults' included) is expanded to `$HOME`.
    pub fn load(paths: &DisckyPaths) -> Result<Config, ConfigError> {
        let mut cfg = match std::fs::read_to_string(&paths.config) {
            Ok(text) => toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: paths.config.clone(),
                source,
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(source) => {
                return Err(ConfigError::Io {
                    path: paths.config.clone(),
                    source,
                });
            }
        };
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(home) = home {
            for root in &mut cfg.scan.roots {
                *root = expand_tilde(root, &home);
            }
        }
        Ok(cfg)
    }

    /// Write the config atomically, creating parent directories as needed: the text goes
    /// to `<config>.tmp`, is synced, then renamed over the config, so a reader (the other
    /// Discky process) never sees a half-written file. A symlinked config is written
    /// through: the rename lands on the link's target, so the link stays.
    pub fn save(&self, paths: &DisckyPaths) -> Result<(), ConfigError> {
        use std::io::Write;
        let text = toml::to_string_pretty(self)?;
        let io_err = |source| ConfigError::Io {
            path: paths.config.clone(),
            source,
        };
        if let Some(parent) = paths.config.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let target = std::fs::canonicalize(&paths.config).unwrap_or_else(|_| paths.config.clone());
        let mut tmp = target.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let written = std::fs::File::create(&tmp).and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.sync_all()
        });
        match written.and_then(|()| std::fs::rename(&tmp, &target)) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(io_err(e))
            }
        }
    }
}

fn expand_tilde(path: &Path, home: &Path) -> PathBuf {
    match path.strip_prefix("~") {
        // `join("")` would leave a trailing slash, shown in messages as `/Users/me/`.
        Ok(rest) if rest.as_os_str().is_empty() => home.to_path_buf(),
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
}
