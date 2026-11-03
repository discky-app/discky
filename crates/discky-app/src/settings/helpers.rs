//! Pure helpers behind the Settings pages: index/value mappings, field texts and list
//! edits. No GPUI imports, so they are unit-tested without a window.

use std::path::{Path, PathBuf};

use discky_core::config::RemovalMode;

use crate::format;

/// The segment index of `mode` in the "Move to Trash / Delete permanently" control.
pub fn removal_mode_index(mode: RemovalMode) -> usize {
    match mode {
        RemovalMode::Trash => 0,
        RemovalMode::Permanent => 1,
    }
}

/// The removal mode of segment `ix`; `None` for an index the control does not have.
pub fn removal_mode_from_index(ix: usize) -> Option<RemovalMode> {
    match ix {
        0 => Some(RemovalMode::Trash),
        1 => Some(RemovalMode::Permanent),
        _ => None,
    }
}

/// The text a threshold field shows for `bytes`: whole decimal megabytes, rounded.
pub fn threshold_field_text(bytes: u64) -> String {
    (bytes.saturating_add(500_000) / 1_000_000).to_string()
}

/// The first `limit` of `paths` shown `~`-relative to `home`, and how many were left out.
pub fn no_access_preview(paths: &[PathBuf], home: &Path, limit: usize) -> (Vec<String>, usize) {
    let shown = paths
        .iter()
        .take(limit)
        .map(|p| format::home_relative(p, home))
        .collect();
    (shown, paths.len().saturating_sub(limit))
}

/// Append `new` to `roots` unless it is already there; whether it was added.
pub fn add_root(roots: &mut Vec<PathBuf>, new: PathBuf) -> bool {
    if roots.contains(&new) {
        return false;
    }
    roots.push(new);
    true
}

/// Append the trimmed glob `pattern` to `list`. `Ok(false)` for an empty or duplicate
/// pattern; `Err` with the `globset` message for an invalid glob.
pub fn add_exclude(list: &mut Vec<String>, pattern: &str) -> Result<bool, String> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Ok(false);
    }
    globset::Glob::new(pattern).map_err(|e| e.to_string())?;
    if list.iter().any(|p| p == pattern) {
        return Ok(false);
    }
    list.push(pattern.to_string());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        add_exclude, add_root, no_access_preview, removal_mode_from_index, removal_mode_index,
        threshold_field_text,
    };
    use discky_core::config::RemovalMode;
    use std::path::{Path, PathBuf};

    #[test]
    fn removal_mode_round_trips_through_index() {
        assert_eq!(removal_mode_index(RemovalMode::Trash), 0);
        assert_eq!(removal_mode_index(RemovalMode::Permanent), 1);
        for m in [RemovalMode::Trash, RemovalMode::Permanent] {
            assert_eq!(removal_mode_from_index(removal_mode_index(m)), Some(m));
        }
        assert_eq!(removal_mode_from_index(2), None);
    }

    #[test]
    fn threshold_text_is_whole_megabytes() {
        assert_eq!(threshold_field_text(500_000_000), "500");
        assert_eq!(threshold_field_text(524_288_000), "524");
        assert_eq!(threshold_field_text(1_500_000), "2");
        assert_eq!(threshold_field_text(1_000_000), "1");
    }

    #[test]
    fn no_access_preview_truncates_and_counts_the_rest() {
        let home = Path::new("/Users/me");
        let paths: Vec<PathBuf> = (0..5)
            .map(|i| home.join(format!("Library/p{i}")))
            .chain([PathBuf::from("/private/var/x")])
            .collect();
        let (shown, rest) = no_access_preview(&paths, home, 3);
        assert_eq!(shown, ["~/Library/p0", "~/Library/p1", "~/Library/p2"]);
        assert_eq!(rest, 3);
        let (shown, rest) = no_access_preview(&paths, home, 50);
        assert_eq!(shown.len(), 6);
        assert_eq!(shown[5], "/private/var/x");
        assert_eq!(rest, 0);
        assert_eq!(no_access_preview(&[], home, 50), (Vec::<String>::new(), 0));
    }

    #[test]
    fn add_root_ignores_duplicates() {
        let mut roots = vec![PathBuf::from("/a")];
        assert!(add_root(&mut roots, PathBuf::from("/b")));
        assert!(!add_root(&mut roots, PathBuf::from("/a")));
        assert!(!add_root(&mut roots, PathBuf::from("/b")));
        assert_eq!(roots, [PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn add_exclude_validates_and_dedupes() {
        let mut list = vec!["**/node_modules".to_string()];
        assert_eq!(add_exclude(&mut list, "  *.iso "), Ok(true));
        assert_eq!(add_exclude(&mut list, "*.iso"), Ok(false));
        assert_eq!(add_exclude(&mut list, "**/node_modules"), Ok(false));
        assert_eq!(add_exclude(&mut list, "   "), Ok(false));
        let err = add_exclude(&mut list, "a[b").unwrap_err();
        assert!(!err.is_empty());
        assert_eq!(list, ["**/node_modules", "*.iso"]);
    }
}
