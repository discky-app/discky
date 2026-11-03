use std::path::{Path, PathBuf};

/// Locations of Discky's persistent files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisckyPaths {
    pub config: PathBuf,
    pub snapshot: PathBuf,
    pub log: PathBuf,
}

impl DisckyPaths {
    /// Resolve the paths. Reads `DISCKY_HOME` on every call (no caching).
    ///
    /// With `DISCKY_HOME` set, all three files live directly inside it;
    /// otherwise the standard macOS locations under `$HOME/Library` are used.
    pub fn resolve() -> DisckyPaths {
        if let Some(home) = std::env::var_os("DISCKY_HOME") {
            let base = PathBuf::from(home);
            return DisckyPaths {
                config: base.join("config.toml"),
                snapshot: base.join("snapshot.bin"),
                log: base.join("removals.log"),
            };
        }
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let support = home.join("Library/Application Support/Discky");
        DisckyPaths {
            config: support.join("config.toml"),
            snapshot: support.join("snapshot.bin"),
            log: home.join("Library/Logs/Discky/removals.log"),
        }
    }
}

/// `p` as a string for JSON and UI text; bytes that are not UTF-8 become U+FFFD.
pub fn display(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
