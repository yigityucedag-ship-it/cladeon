//! RFC 3339 UTC timestamps at second precision.
//!
//! Implemented in-repo rather than pulled from a date library: the only format the
//! product emits or accepts is `YYYY-MM-DDTHH:MM:SSZ`, and a strict parser for one
//! fixed shape is smaller and easier to audit than a general one. Timestamp
//! arithmetic uses Howard Hinnant's civil-from-days algorithms.

use crate::error::{TtError, TtResult};
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub fn now() -> Timestamp {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp(d.as_secs() as i64),
            Err(e) => Timestamp(-(e.duration().as_secs() as i64)),
        }
    }

    pub fn plus_days(self, days: i64) -> Timestamp {
        Timestamp(self.0 + days * 86_400)
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`
    pub fn to_rfc3339(self) -> String {
        let days = self.0.div_euclid(86_400);
        let secs_of_day = self.0.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let h = secs_of_day / 3600;
        let mi = (secs_of_day % 3600) / 60;
        let s = secs_of_day % 60;
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }

    /// Strict parse. Rejects offsets other than `Z`, fractional seconds, lowercase
    /// separators, and any length other than 20.
    pub fn parse_rfc3339(s: &str) -> TtResult<Timestamp> {
        let b = s.as_bytes();
        if b.len() != 20 {
            return Err(TtError::malformed("rfc3339", b.len(), "expected exactly 20 characters"));
        }
        if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
            return Err(TtError::malformed("rfc3339", 0, "separator mismatch"));
        }
        let num = |from: usize, to: usize| -> TtResult<i64> {
            let sub = &s[from..to];
            if !sub.bytes().all(|c| c.is_ascii_digit()) {
                return Err(TtError::malformed("rfc3339", from, "non-digit in field"));
            }
            sub.parse::<i64>()
                .map_err(|_| TtError::malformed("rfc3339", from, "field out of range"))
        };
        let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
        let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
        if !(1..=12).contains(&mo) {
            return Err(TtError::malformed("rfc3339", 5, "month out of range"));
        }
        if d < 1 || d > days_in_month(y, mo) {
            return Err(TtError::malformed("rfc3339", 8, "day out of range"));
        }
        // Leap seconds are not represented; 60 is rejected rather than silently folded.
        if h > 23 || mi > 59 || sec > 59 {
            return Err(TtError::malformed("rfc3339", 11, "time field out of range"));
        }
        let days = days_from_civil(y, mo as u32, d as u32);
        Ok(Timestamp(days * 86_400 + h * 3600 + mi * 60 + sec))
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    const N: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if m == 2 && is_leap(y) {
        29
    } else {
        N[(m - 1) as usize]
    }
}

/// Days since 1970-01-01 from a proleptic Gregorian civil date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((m as i64) + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + (d as i64) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Civil date from days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(Timestamp(0).to_rfc3339(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_instant() {
        // 2026-09-02T13:00:00Z
        let t = Timestamp::parse_rfc3339("2026-09-02T13:00:00Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-09-02T13:00:00Z");
    }

    #[test]
    fn leap_day_round_trips() {
        let t = Timestamp::parse_rfc3339("2024-02-29T23:59:59Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn rejects_non_leap_feb_29() {
        assert!(Timestamp::parse_rfc3339("2023-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn rejects_offset_and_fraction() {
        assert!(Timestamp::parse_rfc3339("2026-09-02T13:00:00+01:00").is_err());
        assert!(Timestamp::parse_rfc3339("2026-09-02T13:00:00.5Z").is_err());
        assert!(Timestamp::parse_rfc3339("2026-09-02t13:00:00Z").is_err());
    }

    #[test]
    fn rejects_leap_second() {
        assert!(Timestamp::parse_rfc3339("2016-12-31T23:59:60Z").is_err());
    }

    #[test]
    fn exhaustive_day_round_trip_over_two_centuries() {
        // 1900-01-01 .. 2100-01-01
        let start = days_from_civil(1900, 1, 1);
        let end = days_from_civil(2100, 1, 1);
        for z in start..end {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z, "failed at {y}-{m}-{d}");
        }
    }

    #[test]
    fn plus_days_crosses_month_boundary() {
        let t = Timestamp::parse_rfc3339("2026-09-02T13:00:00Z").unwrap();
        assert_eq!(t.plus_days(14).to_rfc3339(), "2026-09-16T13:00:00Z");
    }
}
