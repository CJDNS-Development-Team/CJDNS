//! Random number utils

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn seed() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok();
    now.as_ref().map(Duration::as_secs).unwrap_or_default()
}