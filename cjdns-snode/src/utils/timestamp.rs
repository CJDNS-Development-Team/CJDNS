//! Timestamp utilities

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Convert cjdns timestamp to `SystemTime`
pub fn mktime(timestamp: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(timestamp)
}

/// Convert `SystemTime` to cjdns timestamp
pub fn make_timestamp(time: SystemTime) -> u64 {
    let time_since_epoch = time.duration_since(UNIX_EPOCH).expect("internal error: current time before UNIX Epoch");
    time_since_epoch.as_millis() as u64
}

/// Return current system time as cjdns timestamp
pub fn current_timestamp() -> u64 {
    make_timestamp(SystemTime::now())
}

/// Compute duration between two timestamps.
/// It does not matter which of these timestamps is earlier.
pub fn time_diff(t1: SystemTime, t2: SystemTime) -> Duration {
    match t1.duration_since(t2) {
        Ok(d) => d,
        Err(e) => e.duration(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use chrono::{DateTime, SecondsFormat, Utc};
    use tokio::time::Duration;

    use crate::utils::timestamp::time_diff;

    use super::mktime;

    fn t2s(t: SystemTime) -> String {
        let dt = DateTime::<Utc>::from(t);
        dt.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    #[test]
    fn test_mktime() {
        assert_eq!(t2s(mktime(1474857989878)), "2016-09-26T02:46:29.878Z");
    }

    #[test]
    fn test_time_diff() {
        let second = Duration::from_secs(1);
        let t1 = SystemTime::now();
        let t2 = t1 + second;
        assert_eq!(time_diff(t1, t2), second);
        assert_eq!(time_diff(t2, t1), second);
    }
}
