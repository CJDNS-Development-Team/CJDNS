//! Transaction counter.

use std::sync::atomic::{AtomicU64, Ordering};

use rand::Rng;

/// Transaction counter.
pub(super) struct Counter(AtomicU64);

impl Counter {
    pub(super) fn new_random() -> Self {
        let init = rand::thread_rng().gen_range(0, 4_000_000_000);
        Counter(AtomicU64::new(init))
    }

    pub(super) fn next(&self) -> u64 {
        let Counter(ref counter) = self;
        counter.fetch_add(1, Ordering::Relaxed)
    }
}
