//! harbor-watch — CoE tool #2: fitness-for-duty attestation for model
//! weights.
//!
//! The third essay's argument, made executable: "The model was never
//! verified by buying it. It has to prove it is still the same weights,
//! the same configuration, every shift, every day."
//!
//! Laws carried from the estate:
//! - Zero dependencies: pure std; sha512 is the verified Waterfront
//!   implementation; the JSON parser is the Waterfront's.
//! - Files are the truth: enrollments are JSON files, shift logs are
//!   hash-chained JSONL — tamper-evident, re-derivable from bytes alone.
//! - Receipts on every run: every check appends to the shift log; the
//!   log verifies its own chain.
//! - Honesty classes: the tool attests FIT-VS-ENROLLMENT. It cannot
//!   attest that the enrollment itself was clean — that is the
//!   publisher's receipt, not this tool's. Nothing blurred.

pub mod json;
pub mod receipts;
pub mod safetensors;
pub mod sha512;

/// Today as YYYY-MM-DD in UTC (Howard Hinnant's civil-from-days).
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Now as an ISO-8601 UTC timestamp.
pub fn now_ts() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d, hh, mm, ss) = {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let y = yoe + era * 400 + i64::from(m <= 2);
        (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
    };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::today().len(), 10);
        assert_eq!(super::now_ts().len(), 20);
    }
}
