//! Thread-safe sequence number generator.

use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe sequence number generator.
pub struct Seq(AtomicU64);

impl Seq {
    pub fn new(init: u64) -> Self {
        Seq(AtomicU64::new(init))
    }

    pub fn next(&self) -> u64 {
        let Seq(ref counter) = self;
        counter.fetch_add(1, Ordering::Relaxed)
    }
}

#[test]
fn test_seq() {
    let seq = Seq::new(0);
    assert_eq!(seq.next(), 0);
    assert_eq!(seq.next(), 1);
    assert_eq!(seq.next(), 2);
    assert_eq!(seq.next(), 3);
}
