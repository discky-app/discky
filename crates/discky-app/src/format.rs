//! Pure text helpers for the UI: sizes, relative and absolute times, home-relative paths.

use std::path::Path;

/// `n` bytes in decimal units like Finder (1 KB = 1000 B): one decimal below 10,
/// whole numbers above ("9.1 GB", "14 GB", "527 MB").
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1000.0;
    let mut unit = 0;
    loop {
        // Round the way it will be printed; a carry to 1000 moves to the next unit.
        let rounded = if value < 10.0 {
            (value * 10.0).round() / 10.0
        } else {
            value.round()
        };
        if rounded < 1000.0 || unit == UNITS.len() - 1 {
            return if rounded < 10.0 && rounded.fract() != 0.0 {
                format!("{rounded:.1} {}", UNITS[unit])
            } else {
                format!("{rounded:.0} {}", UNITS[unit])
            };
        }
        value /= 1000.0;
        unit += 1;
    }
}

/// How long ago `unix_secs` was, seen from `now` ("just now", "5 min ago", "yesterday", …).
/// Times in the future count as "just now".
pub fn relative(unix_secs: i64, now: i64) -> String {
    const MIN: i64 = 60;
    const HOUR: i64 = 60 * MIN;
    const DAY: i64 = 24 * HOUR;
    const TWO_DAYS: i64 = 2 * DAY;
    const MONTH: i64 = 30 * DAY;
    const YEAR: i64 = 365 * DAY;
    let d = now.saturating_sub(unix_secs);
    let plural = |n: i64, unit: &str| {
        if n == 1 {
            format!("1 {unit} ago")
        } else {
            format!("{n} {unit}s ago")
        }
    };
    if d < 10 {
        "just now".to_string()
    } else if d < MIN {
        format!("{d} s ago")
    } else if d < HOUR {
        format!("{} min ago", d / MIN)
    } else if d < DAY {
        format!("{} h ago", d / HOUR)
    } else if d < TWO_DAYS {
        "yesterday".to_string()
    } else if d < MONTH {
        plural(d / DAY, "day")
    } else if d < YEAR {
        plural(d / MONTH, "month")
    } else {
        plural(d / YEAR, "year")
    }
}

/// `unix_secs` in local time, "2 Nov 21:40"; the year is added when it is not the current one.
pub fn when(unix_secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    match (local_time(unix_secs), local_time(now)) {
        (Some(t), Some(today)) => format_when(&t, today.year),
        // `localtime_r` fails only for times far outside any real file date.
        _ => unix_secs.to_string(),
    }
}

/// `p` with `home` replaced by `~` ("~/Library/Caches/x"), or `p` itself when outside `home`.
pub fn home_relative(p: &Path, home: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.to_string_lossy()),
        Err(_) => p.to_string_lossy().into_owned(),
    }
}

/// `n` with thousands separators ("1,234,567").
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, d) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(d);
    }
    out
}

/// `s` cut from the left to at most `max` characters, the cut marked by a leading "…"
/// ("…/Caches/foo"); `s` itself when it fits.
pub fn shorten_left(s: &str, max: usize) -> String {
    let len = s.chars().count();
    if len <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let tail: String = s.chars().skip(len - keep).collect();
    format!("…{tail}")
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The broken-down local time `when` needs.
struct Tm {
    year: i32,
    /// 0 = January.
    month0: usize,
    day: u32,
    hour: u32,
    min: u32,
}

/// `unix_secs` in the local time zone, via `localtime_r`.
fn local_time(unix_secs: i64) -> Option<Tm> {
    let t: libc::time_t = unix_secs;
    // SAFETY: `tm` is plain old data, so all-zero is a valid value; `localtime_r` writes
    // only into it and reads `t`, and both outlive the call.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    ok.then(|| Tm {
        year: tm.tm_year + 1900,
        month0: tm.tm_mon.clamp(0, 11) as usize,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        min: tm.tm_min as u32,
    })
}

fn format_when(t: &Tm, current_year: i32) -> String {
    let month = MONTHS[t.month0];
    if t.year == current_year {
        format!("{} {month} {:02}:{:02}", t.day, t.hour, t.min)
    } else {
        format!("{} {month} {} {:02}:{:02}", t.day, t.year, t.hour, t.min)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_groups_thousands() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn shorten_left_keeps_the_tail() {
        assert_eq!(shorten_left("~/Library", 60), "~/Library");
        let long = format!("~/{}", "a".repeat(80));
        let s = shorten_left(&long, 60);
        assert_eq!(s.chars().count(), 60);
        assert!(s.starts_with('…'));
        assert!(long.ends_with(&s[s.char_indices().nth(1).map_or(0, |(i, _)| i)..]));
        assert_eq!(shorten_left("абвгд", 3), "…гд");
    }

    #[test]
    fn bytes_decimal_like_finder() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_000), "1 KB");
        assert_eq!(bytes(527_000_000), "527 MB");
        assert_eq!(bytes(9_100_000_000), "9.1 GB");
        assert_eq!(bytes(14_040_000_000), "14 GB");
        assert_eq!(bytes(1_200_000_000_000), "1.2 TB");
    }

    #[test]
    fn bytes_rounding_carries_into_the_next_unit() {
        assert_eq!(bytes(9_960_000_000), "10 GB");
        assert_eq!(bytes(999_600), "1 MB");
        assert_eq!(bytes(1_500), "1.5 KB");
    }

    #[test]
    fn relative_buckets() {
        let now = 1_000_000_000;
        let ago = |secs: i64| relative(now - secs, now);
        assert_eq!(ago(0), "just now");
        assert_eq!(ago(9), "just now");
        assert_eq!(ago(10), "10 s ago");
        assert_eq!(ago(23), "23 s ago");
        assert_eq!(ago(59), "59 s ago");
        assert_eq!(ago(60), "1 min ago");
        assert_eq!(ago(5 * 60), "5 min ago");
        assert_eq!(ago(3_599), "59 min ago");
        assert_eq!(ago(3_600), "1 h ago");
        assert_eq!(ago(3 * 3_600), "3 h ago");
        assert_eq!(ago(86_399), "23 h ago");
        assert_eq!(ago(86_400), "yesterday");
        assert_eq!(ago(2 * 86_400 - 1), "yesterday");
        assert_eq!(ago(2 * 86_400), "2 days ago");
        assert_eq!(ago(3 * 86_400), "3 days ago");
        assert_eq!(ago(29 * 86_400), "29 days ago");
        assert_eq!(ago(30 * 86_400), "1 month ago");
        assert_eq!(ago(61 * 86_400), "2 months ago");
        assert_eq!(ago(364 * 86_400), "12 months ago");
        assert_eq!(ago(365 * 86_400), "1 year ago");
        assert_eq!(ago(2 * 365 * 86_400), "2 years ago");
    }

    #[test]
    fn relative_future_is_just_now() {
        assert_eq!(relative(1_000_000_100, 1_000_000_000), "just now");
    }

    #[test]
    fn when_adds_year_only_outside_current_year() {
        let t = Tm {
            year: 2026,
            month0: 10,
            day: 2,
            hour: 21,
            min: 40,
        };
        assert_eq!(format_when(&t, 2026), "2 Nov 21:40");
        assert_eq!(format_when(&t, 2027), "2 Nov 2026 21:40");
        let early = Tm {
            year: 2026,
            month0: 0,
            day: 15,
            hour: 7,
            min: 5,
        };
        assert_eq!(format_when(&early, 2026), "15 Jan 07:05");
    }

    #[test]
    fn when_uses_local_time() {
        // Smoke test: the real clock path produces "D Mon HH:MM" for the current time.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap();
        let s = when(now);
        let parts: Vec<&str> = s.split(' ').collect();
        assert_eq!(parts.len(), 3, "{s}");
        assert!(MONTHS.contains(&parts[1]), "{s}");
        assert_eq!(parts[2].len(), 5, "{s}");
    }

    #[test]
    fn home_relative_inside_and_outside() {
        let home = Path::new("/Users/me");
        assert_eq!(
            home_relative(Path::new("/Users/me/Library/Caches/x"), home),
            "~/Library/Caches/x"
        );
        assert_eq!(home_relative(Path::new("/Users/me"), home), "~");
        assert_eq!(
            home_relative(Path::new("/Applications/Xcode.app"), home),
            "/Applications/Xcode.app"
        );
        assert_eq!(
            home_relative(Path::new("/Users/meow/x"), home),
            "/Users/meow/x"
        );
    }
}
