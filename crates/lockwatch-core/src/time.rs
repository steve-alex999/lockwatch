//! Minimal date and time helpers.
//!
//! lockwatch needs two things: format "now" for `scanned_at`, and parse the
//! RFC 3339 timestamps in npm registry metadata (`"2026-10-09T12:00:00.123Z"`)
//! for rule LW009. Both are done here on plain Unix seconds (`i64`), which
//! avoids adding a date library. The calendar maths is Howard Hinnant's
//! public-domain `days_from_civil` / `civil_from_days` algorithm.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since 1970-01-01T00:00:00Z.
pub type UnixSeconds = i64;

pub const SECONDS_PER_DAY: i64 = 86_400;

/// The current time. A clock set before 1970 is treated as 1970.
pub fn now() -> UnixSeconds {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a (year, month 1-12, day 1-31) date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Shift the year so it starts in March; February (with the leap day)
    // is then the last month, which makes the formula regular.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400; // 0..=399
    let shifted_month = if month > 2 { month - 3 } else { month + 9 }; // March = 0
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1; // 0..=365
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Inverse of [`days_from_civil`]: (year, month, day) for a day number.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Format as `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds).
pub fn format_rfc3339(t: UnixSeconds) -> String {
    let days = t.div_euclid(SECONDS_PER_DAY);
    let secs = t.rem_euclid(SECONDS_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`.
/// Returns `None` for anything else. Fractions of a second are ignored.
pub fn parse_rfc3339(s: &str) -> Option<UnixSeconds> {
    let b = s.as_bytes();
    // Parse the decimal digits in s[start..end] as a number.
    // `s.get(range)` returns None instead of panicking when out of range.
    let num = |start: usize, end: usize| -> Option<i64> {
        let part = s.get(start..end)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // Skip an optional fraction like ".123".
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset_seconds = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let minutes = num(i + 1, i + 3)? * 60 + num(i + 4, i + 6)?;
            if *sign == b'+' {
                minutes * 60
            } else {
                -minutes * 60
            }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    Some(days * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second - offset_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        // 2000-02-29 is a leap day; 951782400 is its Unix time.
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(format_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn round_trips_many_days() {
        // Every day from 1960 to 2100 (in steps) survives format -> parse.
        let mut t = -315_619_200; // 1960-01-01
        while t < 4_102_444_800 {
            let text = format_rfc3339(t + 3_723);
            assert_eq!(parse_rfc3339(&text), Some(t + 3_723), "{text}");
            t += SECONDS_PER_DAY * 13;
        }
    }

    #[test]
    fn parses_fractions_and_offsets() {
        let base = parse_rfc3339("2026-10-09T12:00:00Z").expect("valid");
        assert_eq!(parse_rfc3339("2026-10-09T12:00:00.987Z"), Some(base));
        assert_eq!(parse_rfc3339("2026-10-09T14:00:00+02:00"), Some(base));
        assert_eq!(parse_rfc3339("2026-10-09T07:30:00-04:30"), Some(base));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "2026-10-09",
            "2026-13-01T00:00:00Z",
            "2026-10-09T25:00:00Z",
            "2026-10-09T12:00:00",
            "2026-10-09T12:00:00Zjunk",
            "abcd-10-09T12:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
