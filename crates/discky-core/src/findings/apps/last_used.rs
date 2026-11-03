//! When an app was last used: Spotlight's `kMDItemLastUsedDate`, or an estimate from the
//! newest leftover when Spotlight has nothing. Also every bundle id Spotlight knows
//! ([`spotlight_bundle_ids`]), which decides what counts as installed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::LastUsed;
use crate::tools::run_capture;

const MDFIND_TIMEOUT: Duration = Duration::from_secs(5);
const ATTR: &str = "kMDItemLastUsedDate";
const ID_ATTR: &str = "kMDItemCFBundleIdentifier";
const QUERY: &str = "kMDItemContentType == 'com.apple.application-bundle'";

/// Last-used dates of every app bundle Spotlight knows under `roots`: one
/// `mdfind -attr kMDItemLastUsedDate "<app bundles>" -onlyin <root>` per root (5 s each).
/// Bundles without a date are absent. `None` (no mdfind) → empty.
pub fn spotlight_last_used(mdfind: Option<&Path>, roots: &[&Path]) -> HashMap<PathBuf, i64> {
    let Some(mdfind) = mdfind else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for root in roots {
        let Some(root) = root.to_str() else {
            continue;
        };
        let args = ["-attr", ATTR, QUERY, "-onlyin", root];
        if let Some(text) = run_capture(mdfind, &args, MDFIND_TIMEOUT) {
            out.extend(text.lines().filter_map(parse_mdfind_line));
        }
    }
    out
}

/// Bundle id → display name of every app bundle Spotlight knows, anywhere (iOS apps,
/// apps deeper than the folders walked, other volumes): one
/// `mdfind -attr kMDItemCFBundleIdentifier "<app bundles>"` (5 s). `None` when there is no
/// mdfind, it fails or times out, or it knows no app at all (Spotlight indexing off) —
/// then what is installed cannot be verified.
pub fn spotlight_bundle_ids(mdfind: Option<&Path>) -> Option<HashMap<String, String>> {
    let text = run_capture(mdfind?, &["-attr", ID_ATTR, QUERY], MDFIND_TIMEOUT)?;
    Some(parse_bundle_ids(&text)).filter(|ids| !ids.is_empty())
}

/// Lines `<path>   kMDItemCFBundleIdentifier = <id>` (the id bare or in double quotes)
/// ⇒ id → the bundle's file stem; `(null)` and other shapes are left out. The first path
/// of an id names it.
pub fn parse_bundle_ids(text: &str) -> HashMap<String, String> {
    let marker = format!(" {ID_ATTR} = ");
    let mut out = HashMap::new();
    for line in text.lines() {
        let Some(i) = line.rfind(&marker) else {
            continue;
        };
        let path = Path::new(line[..i].trim_end());
        let raw = line[i + marker.len()..].trim();
        let id = raw
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .unwrap_or(raw);
        if id.is_empty() || id == "(null)" || id.contains(char::is_whitespace) {
            continue;
        }
        let name = path
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| id.to_string());
        out.entry(id.to_string()).or_insert(name);
    }
    out
}

/// `<path>   kMDItemLastUsedDate = 2026-11-03 12:35:08 +0000` ⇒ `(path, unix seconds)`;
/// `None` for `(null)` or any other shape.
pub fn parse_mdfind_line(line: &str) -> Option<(PathBuf, i64)> {
    let marker = format!(" {ATTR} = ");
    let i = line.rfind(&marker)?;
    let path = line[..i].trim_end();
    if path.is_empty() {
        return None;
    }
    let t = parse_utc(line[i + marker.len()..].trim())?;
    Some((PathBuf::from(path), t))
}

/// `YYYY-MM-DD HH:MM:SS ±HHMM` ⇒ unix seconds (proleptic Gregorian, no leap seconds).
pub(crate) fn parse_utc(s: &str) -> Option<i64> {
    let mut parts = s.split_whitespace();
    let (date, time, offset) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let num = |s: &str, len: usize| -> Option<i64> {
        (s.len() == len && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let mut d = date.split('-');
    let (y, m, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    let mut t = time.split(':');
    let (hh, mm, ss) = (num(t.next()?, 2)?, num(t.next()?, 2)?, num(t.next()?, 2)?);
    if d.next().is_some() || t.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let sign = match offset.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let off = num(&offset[1..], 4)?;
    let off_secs = sign * ((off / 100) * 3600 + (off % 100) * 60);
    let days = days_from_civil(y, m, day);
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - off_secs)
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The newest of the leftovers' modification times as an estimate; no (positive) times →
/// [`LastUsed::Unknown`].
pub fn estimate_from(leftover_mtimes: &[i64]) -> LastUsed {
    leftover_mtimes
        .iter()
        .copied()
        .filter(|&t| t > 0)
        .max()
        .map_or(LastUsed::Unknown, LastUsed::Estimated)
}

/// Spotlight's date when there is one, else [`estimate_from`] the leftovers.
pub fn resolve(spotlight: Option<i64>, leftover_mtimes: &[i64]) -> LastUsed {
    spotlight.map_or_else(|| estimate_from(leftover_mtimes), LastUsed::Spotlight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_utc_matches_date_u() {
        // `date -u -j -f "%Y-%m-%d %H:%M:%S" "2026-11-03 12:35:08" +%s`
        assert_eq!(parse_utc("2026-11-03 12:35:08 +0000"), Some(1_793_709_308));
        assert_eq!(parse_utc("2026-10-29 21:16:29 +0000"), Some(1_793_308_589));
        assert_eq!(parse_utc("1970-01-01 00:00:00 +0000"), Some(0));
        assert_eq!(parse_utc("2024-02-29 23:59:59 +0000"), Some(1_709_251_199));
        assert_eq!(parse_utc("1970-01-01 03:00:00 +0300"), Some(0));
        assert_eq!(parse_utc("1969-12-31 23:00:00 -0100"), Some(0));
    }

    #[test]
    fn parse_utc_rejects_malformed() {
        for s in [
            "",
            "(null)",
            "2026-11-03",
            "2026-11-03 12:35:08",
            "2026-13-03 12:35:08 +0000",
            "2026-11-03 24:00:00 +0000",
            "2026-11-03 12:35:08 0000",
            "26-11-03 12:35:08 +0000",
            "2026-11-03 12:35:08 +0000 extra",
            "2026-11-03 12:35 +0000",
        ] {
            assert_eq!(parse_utc(s), None, "{s:?}");
        }
    }
}
