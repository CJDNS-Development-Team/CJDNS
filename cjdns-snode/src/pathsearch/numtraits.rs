//! Dijkstra algorithm helper traits.

/// Helper trait providing zero value for numeric types.
pub trait Zero {
    const ZERO: Self;
}

impl Zero for f64 {
    const ZERO: f64 = 0.0;
}

/// Helper trait, providing total ordering for non-`Ord` types,
/// such as `f64`, given its value is finite (i.e. not `NaN`, `Infinity` etc.)
pub trait IntoOrd where Self::Output: Ord {
    /// Some substitute `Ord` type which can be used instead of `Self` for ordering purposes.
    /// Only should be used for comparisons, its value itself is meaningless.
    type Output;

    /// Convert self into `Ord`-supporting type `Self::Output`.
    fn into_ord(self) -> Self::Output;
}

impl IntoOrd for f64 {
    type Output = i64;

    fn into_ord(self) -> Self::Output {
        debug_assert!(self.is_finite(), "Non-finite weight detected: {}", self);
        // For the explanation of this black magic,
        // see implementation of `f64::total_ord()` (unstable as of Rust 1.46)
        let x = self.to_bits() as i64;
        x ^ (((x >> 63) as u64) >> 1) as i64
    }
}

#[test]
fn test_into_ord_f64() {
    let ord = |x: f64| x.into_ord();
    assert!(ord(0.0) > ord(-1.0));
    assert!(ord(0.0) < ord(1.0));
    assert!(ord(-1.0) < ord(1.0));
    assert!(ord(2.0) > ord(1.0));
    assert!(ord(-2.0) < ord(-1.0));
    assert!(ord(100.0) > ord(10.0));
}