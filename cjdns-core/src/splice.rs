//! Routing label splice/unsplice routines.

use thiserror::Error;

use crate::{EncodingScheme, EncodingSchemeForm, LabelBits, PathHop, RoutingLabel, schemes};

/// Result type alias.
pub type Result<T> = std::result::Result<T, SpliceError>;

/// Error type.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SpliceError {
    #[error("Label is too long")]
    LabelTooLong,
    #[error("Not enough arguments")]
    NotEnoughArguments,
    #[error("Bad argument")]
    BadArgument,
    #[error("Can't unsplice")]
    CannotUnsplice,
    #[error("Can't detect form")]
    CannotFindForm,
    #[error("Can't re-encode")]
    CannotReencode,
}

/// This function takes one or more `RoutingLabel`s and splices them to create a resulting label.
///
/// If you have a peer at `0000.0000.0000.0013` and he has a peer at `0000.0000.0000.0015` which you
/// want to reach, you can splice a label for reaching him as in example below.
///
/// Remember that the arguments should be read right to left, the first hop is the furthest to the right in the splice function.
/// If the result of the splicing is too long to fit in a label (`LabelBits<T>::MAX_PAYLOAD_BITS` bits)
/// then it will return `Err(Error::LabelTooLong)`.
///
/// ```rust
/// # use cjdns_core::splice::splice;
/// # use cjdns_core::RoutingLabel;
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// let result = splice(&[l("0000.0000.0000.0015"), l("0000.0000.0000.0013")]);
/// assert_eq!(result, Ok(l("0000.0000.0000.0153")));
/// ```
///
/// Splice only works to splice a route if the return route is the same size or smaller. If the return
/// route is larger then the smaller director in the path must be re-encoded to be the same size as
/// the return path director. `build_label()` will take care of this automatically.
///
/// See: [LabelSplicer_splice()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/LabelSplicer.h#L36)
pub fn splice<L: LabelBits>(labels: &[RoutingLabel<L>]) -> Result<RoutingLabel<L>> {
    if labels.len() < 2 {
        return Err(SpliceError::NotEnoughArguments);
    }

    let mut result_bits = labels[0].bits();
    for addon in &labels[1..] {
        let addon_bitlen = label_highest_set_bit(addon);
        let result_hsb = result_bits.highest_set_bit().expect("zero"); // All labels are always non-zero, so highest_set_bit() always available
        if result_hsb + addon_bitlen > L::MAX_PAYLOAD_BITS - 1 {
            return Err(SpliceError::LabelTooLong);
        }

        result_bits = ((result_bits ^ L::ONE) << addon_bitlen) ^ addon.bits();
    }

    RoutingLabel::try_new(result_bits).ok_or(()).map_err(|_| unreachable!("result_bits is zero"))
}

/// Get the **encoding form** used for the first **director** of the `RoutingLabel`.
/// It also returns index of found **form** in **scheme**.
/// Recall an encoding **scheme** is one or more encoding **forms**.
/// If the label is not recognized as using the given scheme then it'll return `Err(Error::CannotFindForm)`.
///
/// ```rust
/// # use cjdns_core::splice::get_encoding_form;
/// # use cjdns_core::{RoutingLabel, schemes, EncodingSchemeForm};
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// # let encoding_form = |bit_count, prefix_len, prefix| EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).expect("invalid encoding form");
/// let form = get_encoding_form(l("0000.0000.0000.0013"), &schemes::V358);
/// assert_eq!(form, Ok((encoding_form(3, 1, 1), 0)));
///
/// let form = get_encoding_form(l("0000.0000.0000.1110"), &schemes::V358);
/// assert_eq!(form, Ok((encoding_form(8, 2, 0), 2)));
/// ```
///
/// See: [EncodingScheme_getFormNum()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/EncodingScheme.c#L23)
pub fn get_encoding_form<L: LabelBits>(label: RoutingLabel<L>, scheme: &EncodingScheme) -> Result<(EncodingSchemeForm, usize)> {
    for (i, form) in scheme.iter().enumerate() {
        let (_, prefix_len, prefix) = form.params();
        if 0 == prefix_len {
            return Ok((*form, i));
        }

        assert!(prefix_len < 32, "encoding scheme with invalid form");
        let mask = (1u32 << (prefix_len as u32)) - 1u32;
        if label.bits() & mask.into() == prefix.into() {
            return Ok((*form, i));
        }
    }

    Err(SpliceError::CannotFindForm)
}

/// Extracts a director stripping the encoding.
#[inline]
fn get_director<L: LabelBits>(label: RoutingLabel<L>, form: EncodingSchemeForm) -> L {
    let (bit_count, prefix_len, _) = form.params();
    let padding = L::BIT_SIZE - bit_count as u32 - prefix_len as u32;
    (label.bits() << padding) >> (padding + prefix_len as u32)
}

/// Bit length of a director (not a label, e.g. without self-route).
#[inline]
fn director_bit_length<L: LabelBits>(dir: L) -> u32 {
    dir.highest_set_bit().unwrap_or(0u32) + 1u32
}

#[test]
fn test_director_bit_length() {
    assert_eq!(director_bit_length(0_u64), 1);
    assert_eq!(director_bit_length(1_u64), 1);
    assert_eq!(director_bit_length(2_u64), 2);
    assert_eq!(director_bit_length(3_u64), 2);
    assert_eq!(director_bit_length(4_u64), 3);
    assert_eq!(director_bit_length(0xFFFF_u64), 16);
    assert_eq!(director_bit_length(0xFFFFFFFF_u64), 32);
    assert_eq!(director_bit_length(0xFFFFFFFFFFFFFFFF_u64), 64);
}

/// Index of highest set bit in label's binary representation.
#[inline]
fn label_highest_set_bit<L: LabelBits>(label: &RoutingLabel<L>) -> u32 {
    label.bits().highest_set_bit().expect("zero label")
}

#[test]
fn test_label_highest_set_bit() {
    let l64 = |v: u64| -> RoutingLabel<u64> { RoutingLabel::try_new(v).expect("bad label") };
    let l128 = |v: u128| -> RoutingLabel<u128> { RoutingLabel::try_new(v).expect("bad label") };

    assert_eq!(label_highest_set_bit(&l64(1)), 0);
    assert_eq!(label_highest_set_bit(&l64(2)), 1);
    assert_eq!(label_highest_set_bit(&l64(14574489829)), 33);
    assert_eq!(label_highest_set_bit(&l128(14574489829)), 33);
    assert_eq!(label_highest_set_bit(&l64(1 << 63)), 63);
    assert_eq!(label_highest_set_bit(&l128(1 << 100)), 100);
}

/// Detects canonical (shortest) form which has enough space to hold `dir`.
fn find_shortest_form<L: LabelBits>(dir: L, scheme: &EncodingScheme) -> Result<EncodingSchemeForm> {
    let dir_bits = director_bit_length(dir);

    scheme
        .iter()
        .filter(|&form| (form.params().0 as u32) >= dir_bits)
        .min_by_key(|&form| form.params().0)
        .map(|&form| form)
        .ok_or(SpliceError::CannotFindForm)
}

/// Re-encode a `label` to the encoding form specified by `desired_form_num`
/// (or canonical if `None`).
///
/// This will re-encode a label to the **encoding form** specified by `desired_form_num`.
/// This may return an error if the encoding form cannot
/// be detected, you pass an invalid **desired_form_num** or if you try to re-encode the self route
/// (`0001`). It will also return an error if re-encoding a label will make it too long (more than `Label::max_bit_size()`
/// bits). If desired_form_num is `None` then it will re-encode the label
/// into it's *cannonical* form, that is the smallest form which can hold that director.
///
/// ```rust
/// # use cjdns_core::splice::re_encode;
/// # use cjdns_core::{RoutingLabel, schemes};
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// let r = re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(0));
/// assert_eq!(r, Ok(l("0000.0000.0000.0015")));
///
/// let r = re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(1));
/// assert_eq!(r, Ok(l("0000.0000.0000.0086")));
///
/// let r = re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(2));
/// assert_eq!(r, Ok(l("0000.0000.0000.0404")));
///
/// let r = re_encode(l("0000.0000.0000.0404"), &schemes::V358, None);
/// assert_eq!(r, Ok(l("0000.0000.0000.0015")));
/// ```
///
/// See: [EncodingScheme_convertLabel()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/EncodingScheme.c#L56)
pub fn re_encode<L: LabelBits>(label: RoutingLabel<L>, scheme: &EncodingScheme, desired_form_num: Option<usize>) -> Result<RoutingLabel<L>> {
    let (form, _) = get_encoding_form(label, scheme)?;
    let mut dir = get_director(label, form);

    let mut desired_form = if let Some(num) = desired_form_num {
        if num >= scheme.len() {
            return Err(SpliceError::BadArgument);
        }
        scheme[num]
    } else {
        find_shortest_form(dir, scheme)?
    };
    let (desired_bit_count, desired_prefix_len, desired_prefix) = desired_form.params();

    if *scheme == *schemes::V358 {
        // Special magic for SCHEME_358 legacy.
        fn is_358_zero_form(f: EncodingSchemeForm) -> bool {
            f == schemes::V358[0]
        }

        if is_358_zero_form(desired_form) && dir == 0b111_u32.into() {
            desired_form = schemes::V358[1];
        }

        if is_358_zero_form(form) {
            if dir == L::ZERO {
                return Err(SpliceError::CannotReencode);
            }
            dir = dir - L::ONE;
        }
        if is_358_zero_form(desired_form) {
            dir = dir + L::ONE;
        }
    }

    // Construct result: [bits before extracted dir][padded dir][desired form prefix]
    let mut result_bits = {
        let (bit_count, prefix_len, _) = form.params();
        label.bits() >> (bit_count as u32 + prefix_len as u32)
    };

    // check for overflow
    let rest_bitlen = match result_bits.highest_set_bit() {
        None => 0,
        Some(len) => len + 1,
    };
    let used_bits = rest_bitlen + desired_bit_count as u32 + desired_prefix_len as u32;
    if used_bits > L::MAX_PAYLOAD_BITS {
        return Err(SpliceError::LabelTooLong);
    }

    result_bits = (result_bits << (desired_bit_count as u32)) | dir;
    result_bits = (result_bits << (desired_prefix_len as u32)) | desired_prefix.into();

    RoutingLabel::try_new(result_bits).ok_or(()).map_err(|_| unreachable!("result_bits is zero"))
}

/// Tests if a `label` contains only one hop.
///
/// The `encoding_scheme` argument is the one used by the node which is at the beginning of the path given by the `label`.
///
/// ```rust
/// # use cjdns_core::splice::is_one_hop;
/// # use cjdns_core::{RoutingLabel, schemes};
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// assert_eq!(is_one_hop(l("0000.0000.0000.0013"), &schemes::V358), Ok(true));
/// assert_eq!(is_one_hop(l("0000.0000.0000.0015"), &schemes::V358), Ok(true));
/// assert_eq!(is_one_hop(l("0000.0000.0000.0153"), &schemes::V358), Ok(false));
/// ```
///
/// See: [EncodingScheme_isOneHop()](https://github.com/cjdelisle/cjdns/blob/77259a49e5bc7ca7bc6dca5bd423e02be563bdc5/switch/EncodingScheme.c#L451)
pub fn is_one_hop<L: LabelBits>(label: RoutingLabel<L>, encoding_scheme: &EncodingScheme) -> Result<bool> {
    let (label_form, _) = get_encoding_form(label, encoding_scheme)?;
    let (bit_count, prefix_len, _) = label_form.params();
    let form_bits = (bit_count + prefix_len) as u32;
    Ok(label_highest_set_bit(&label) == form_bits)
}

/// This will construct a label using an array representation of a path (`path_hops`).
/// If any label along the path needs to be re-encoded, it will be.
///
/// Each element in the array represents a hop (node) in the path and each of them has `PathHop.label_p` and/or `PathHop.label_n`
/// depending on whether there is a previous and/or next hop.
/// `PathHop.label_p` is necessary to know the width of the inverse path hop so that the label can be re-encoded if necessary.
///
/// ```rust
/// # use cjdns_core::splice::build_label;
/// # use cjdns_core::{PathHop, RoutingLabel, schemes};
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).ok();
/// let label = build_label(&[
///     PathHop::new(l("0000.0000.0000.0000"), l("0000.0000.0000.0015"), &schemes::V358),
///     PathHop::new(l("0000.0000.0000.009e"), l("0000.0000.0000.008e"), &schemes::V358),
///     PathHop::new(l("0000.0000.0000.0013"), l("0000.0000.0000.00a2"), &schemes::V358),
///     PathHop::new(l("0000.0000.0000.001b"), l("0000.0000.0000.001d"), &schemes::V358),
///     PathHop::new(l("0000.0000.0000.00ee"), l("0000.0000.0000.001b"), &schemes::V358),
///     PathHop::new(l("0000.0000.0000.0019"), l("0000.0000.0000.001b"), &schemes::V358),
///     PathHop::new(l("0000.0000.0000.0013"), l("0000.0000.0000.0000"), &schemes::V358),
/// ]);
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// let expected = (
///     l("0000.0003.64b5.10e5"),
///     vec![
///         l("0000.0000.0000.0015"),
///         l("0000.0000.0000.008e"),
///         l("0000.0000.0000.00a2"),
///         l("0000.0000.0000.001d"),
///         l("0000.0000.0000.0092"),
///         l("0000.0000.0000.001b"),
///     ]
/// );
/// assert_eq!(label, Ok(expected));
/// ```
/// This function results in a tuple containing 2 elements, `label` and `path`. `label` is the final label for this `path`. And `path` is the hops to get there.
/// Notice the second to last hop in the `path` has been changed from 001b to 0092. This is a re-encoding to ensure that the `label` remains the right length as the reverse path for this hop is 00ee which is longer than 001b.
pub fn build_label<L: LabelBits>(path_hops: &[PathHop<L>]) -> Result<(RoutingLabel<L>, Vec<RoutingLabel<L>>)> {
    if path_hops.len() < 2 {
        return Err(SpliceError::NotEnoughArguments);
    }

    if let (Some(first_hop), Some(last_hop)) = (path_hops.first(), path_hops.last()) {
        assert!(path_hops.len() >= 2); // Because there exist first() and last()
        let mid_hops = &path_hops[1..path_hops.len() - 1];
        build_label_impl(first_hop, mid_hops, last_hop)
    } else {
        unreachable!() // because of the `path_hops.len()` check above
    }
}

fn build_label_impl<L: LabelBits>(first_hop: &PathHop<L>, mid_hops: &[PathHop<L>], last_hop: &PathHop<L>) -> Result<(RoutingLabel<L>, Vec<RoutingLabel<L>>)> {
    let first_hop_label_n = first_hop.label_n.ok_or(SpliceError::BadArgument)?; // must be Some
    let _last_hop_label_p = last_hop.label_p.ok_or(SpliceError::BadArgument)?; // must be Some
    first_hop.label_p.map_or(Ok(()), |_| Err(SpliceError::BadArgument))?; // must be None
    last_hop.label_n.map_or(Ok(()), |_| Err(SpliceError::BadArgument))?; // must be None

    let mut ret_path = Vec::with_capacity(mid_hops.len() + 1);
    ret_path.push(first_hop_label_n);

    // Iterate over hops except for first and last
    for hop in mid_hops {
        if let (Some(label_p), Some(mut label_n)) = (hop.label_p, hop.label_n) {
            let (form_label_p, form_idx) = get_encoding_form(label_p, hop.encoding_scheme)?;
            let (form_label_n, _) = get_encoding_form(label_n, hop.encoding_scheme)?;
            let (label_p_bit_count, label_p_prefix_len, _) = form_label_p.params();
            let (label_n_bit_count, label_n_prefix_len, _) = form_label_n.params();
            if label_p_bit_count + label_p_prefix_len > label_n_bit_count + label_n_prefix_len {
                label_n = re_encode(label_n, hop.encoding_scheme, Some(form_idx))?;
            }

            ret_path.push(label_n);
        } else {
            return Err(SpliceError::BadArgument);
        }
    }

    let ret_label = if ret_path.len() > 1 {
        let mut y = ret_path.clone();
        y.reverse();
        splice(&y)?
    } else {
        first_hop_label_n
    };

    Ok((ret_label, ret_path))
}

/// This will return `true` if the node at the end of the route given by `mid_path` is a hop along the path given by `destination`.
///
/// ```rust
/// # use cjdns_core::splice::routes_through;
/// # use cjdns_core::RoutingLabel;
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// assert_eq!(routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0015")), true);
/// assert_eq!(routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0013")), false);
/// ```
///
/// See: [LabelSplicer_routesThrough()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/LabelSplicer.h#L52)
pub fn routes_through<L: LabelBits>(destination: RoutingLabel<L>, mid_path: RoutingLabel<L>) -> bool {
    let (dest_highest_set_bit, mid_path_highest_set_bit) = (label_highest_set_bit(&destination), label_highest_set_bit(&mid_path));
    if dest_highest_set_bit < mid_path_highest_set_bit {
        return false;
    }
    let mask = (L::ONE << mid_path_highest_set_bit) - L::ONE;
    destination.bits() & mask == mid_path.bits() & mask
}

/// Convert a full path to a representation which a node along that path can use.
///
/// This will output a value which if passed to `splice()` with the input `mid_path`, would yield the input `destination`.
/// If `routes_through(destination, mid_path)` would return `false`, this returns an `Err(Error::CannotUnsplice)`.
///
/// ```rust
/// # use cjdns_core::splice::{splice, unsplice};
/// # use cjdns_core::RoutingLabel;
/// # use std::convert::TryFrom;
/// # let l = |s: &str| RoutingLabel::<u64>::try_from(s).unwrap();
/// assert_eq!(splice(&[l("0000.0000.0000.0015"), l("0000.0000.0000.0013")]), Ok(l("0000.0000.0000.0153")));
/// assert_eq!(unsplice(l("0000.0000.0000.0153"), l("0000.0000.0000.0013")), Ok(l("0000.0000.0000.0015")));
/// ```
///
/// See: [LabelSplicer_unsplice()](https://github.com/cjdelisle/cjdns/blob/77259a49e5bc7ca7bc6dca5bd423e02be563bdc5/switch/LabelSplicer.h#L31)
pub fn unsplice<L: LabelBits>(destination: RoutingLabel<L>, mid_path: RoutingLabel<L>) -> Result<RoutingLabel<L>> {
    if !(routes_through(destination, mid_path)) {
        return Err(SpliceError::CannotUnsplice);
    }

    RoutingLabel::try_new(destination.bits() >> label_highest_set_bit(&mid_path)).ok_or(()).map_err(|_| unreachable!("highest_set_bit() is broken"))
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::{RoutingLabel, schemes};

    use super::*;

    fn l(v: &str) -> RoutingLabel<u64> {
        RoutingLabel::try_from(v).expect("bad test data")
    }

    fn lopt(v: &str) -> Option<RoutingLabel<u64>> {
        RoutingLabel::try_from(v).ok()
    }

    fn l128(v: &str) -> RoutingLabel<u128> {
        RoutingLabel::<u128>::try_from(v).expect("bad test data")
    }

    fn l128opt(v: &str) -> Option<RoutingLabel<u128>> {
        RoutingLabel::<u128>::try_from(v).ok()
    }

    fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
        EncodingScheme::try_new(forms).expect("invalid scheme")
    }

    fn encoding_form(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
        EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).expect("invalid form")
    }

    #[test]
    fn test_splice() {
        assert_eq!(splice::<u64>(&[]), Err(SpliceError::NotEnoughArguments));
        assert_eq!(
            splice(&[l("0000.0000.0000.0015")]),
            Err(SpliceError::NotEnoughArguments)
        );

        assert_eq!(
            splice(&[l("0000.0000.0000.0015"), l("0000.0000.0000.0013")]),
            Ok(l("0000.0000.0000.0153"))
        );

        assert_eq!(
            splice(&[
                l128("0000.0000.0000.0000.0000.0000.0000.0015"),
                l128("0000.0000.0000.0000.0000.0000.0000.0013")
            ]),
            Ok(l128("0000.0000.0000.0000.0000.0000.0000.0153"))
        );

        let mut labels = [
            l("0000.0000.0000.0015"),
            l("0000.0000.0000.008e"),
            l("0000.0000.0000.00a2"),
            l("0000.0000.0000.001d"),
            l("0000.0000.0000.0414"),
            l("0000.0000.0000.001b"),
        ];
        labels.reverse();
        assert_eq!(splice(&labels), Ok(l("0000.001b.0535.10e5")));

        let mut labels128 = [
            l128("0000.0000.0000.0000.0000.0000.0000.0015"),
            l128("0000.0000.0000.0000.0000.0000.0000.008e"),
            l128("0000.0000.0000.0000.0000.0000.0000.00a2"),
            l128("0000.0000.0000.0000.0000.0000.0000.001d"),
            l128("0000.0000.0000.0000.0000.0000.0000.0414"),
            l128("0000.0000.0000.0000.0000.0000.0000.001b"),
        ];
        labels128.reverse();
        assert_eq!(
            splice(&labels128),
            Ok(l128("0000.0000.0000.0000.0000.001b.0535.10e5"))
        );
    }

    #[test]
    fn test_splice_long_label() {
        assert_eq!(
            splice(&[l("0200.0000.0000.1111"), l("0000.0000.0000.0005")]),
            Ok(l("0800.0000.0000.4445"))
        );
        assert_eq!(
            splice(&[
                l128("0200.0000.0000.0000.0000.0000.0000.1111"),
                l128("0000.0000.0000.0000.0000.0000.0000.0005")
            ]),
            Ok(l128("0800.0000.0000.0000.0000.0000.0000.4445"))
        );

        assert_eq!(
            splice(&[l("0400.0000.0000.1111"), l("0000.0000.0000.0005")]),
            Err(SpliceError::LabelTooLong)
        );
        assert_eq!(
            splice(&[
                l128("0400.0000.0000.0000.0000.0000.0000.1111"),
                l128("0000.0000.0000.0000.0000.0000.0000.0005")
            ]),
            Err(SpliceError::LabelTooLong)
        );
    }

    #[test]
    fn test_get_encoding_form() {
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &schemes::F8),
            Ok((
                encoding_form(8, 0, 0),
                0
            ))
        );

        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1110"), &schemes::V358),
            Ok((
                encoding_form(8, 2, 0),
                2
            ))
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &schemes::V358),
            Ok((
                encoding_form(3, 1, 1),
                0
            ))
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1112"), &schemes::V358),
            Ok((
                encoding_form(5, 2, 2),
                1
            ))
        );

        assert_eq!(
            get_encoding_form(l("0000.0000.0000.0013"), &schemes::V358),
            Ok((
                encoding_form(3, 1, 1),
                0
            ))
        );

        assert!(get_encoding_form(
            l("0000.0000.0000.1113"),
            &encoding_scheme(&[
                encoding_form(5, 2, 2),
                encoding_form(8, 2, 0),
            ])
        )
        .is_err());
    }

    #[test]
    fn test_find_shortest_form() {
        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0002").bits(), &schemes::F4),
            Ok(encoding_form(4, 0, 0))
        );
        assert!(find_shortest_form(l("0000.0000.0000.0010").bits(), &schemes::F4).is_err());

        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0002").bits(), &schemes::V48),
            Ok(encoding_form(4, 1, 1))
        );
        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0010").bits(), &schemes::V48),
            Ok(encoding_form(8, 1, 0))
        );
        assert!(find_shortest_form(l("0000.0000.0000.0100").bits(), &schemes::V48).is_err());

        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0015").bits(), &schemes::V358),
            Ok(encoding_form(5, 2, 2))
        );
    }

    #[test]
    fn test_reencode_basic() {
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(2)),
            Ok(l("0000.0000.0000.0404"))
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(1)),
            Ok(l("0000.0000.0000.0086"))
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(0)),
            Ok(l("0000.0000.0000.0015"))
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0404"), &schemes::V358, None),
            Ok(l("0000.0000.0000.0015"))
        );

        assert!(re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(3)).is_err());
        assert!(re_encode(l("0000.0000.0000.0015"), &schemes::V358, Some(4)).is_err());

        assert!(re_encode(
            l("0000.0000.0000.1113"),
            &encoding_scheme(&[
                encoding_form(5, 2, 2),
                encoding_form(8, 2, 0),
            ]),
            None
        )
        .is_err());

        assert_eq!(
            re_encode(l("0040.0000.0000.0067"), &schemes::V48, Some(1)),
            Ok(l("0400.0000.0000.0606"))
        );
        assert!(re_encode(l("0400.0000.0000.0067"), &schemes::V48, Some(1)).is_err());
    }

    #[test]
    fn test_reencode_big() {
        fn test_scheme(scheme: &EncodingScheme) {
            let biggest_form = *(scheme.last().expect("bad test"));
            let biggest_form_num = scheme.len() - 1;
            let (bit_count, prefix_len, prefix) = biggest_form.params();
            let max = ((1u64 << (bit_count as u64)) - 1) as u32;

            for i in 0..max {
                let full_label_bits = (1_u64 << (bit_count as u32 + prefix_len as u32))
                    | ((i as u64) << (prefix_len as u32))
                    | (prefix as u64);
                let full_label = RoutingLabel::try_new(full_label_bits).expect("bad test data");

                let dir_bit_count = director_bit_length(i as u64);
                for (form_num, form) in scheme.into_iter().enumerate() {
                    if (form.params().0 as u32) < dir_bit_count {
                        continue;
                    }

                    let med = re_encode(full_label, scheme, Some(form_num)).expect("bad test");
                    assert_eq!(
                        re_encode(med, scheme, Some(biggest_form_num)),
                        Ok(full_label)
                    );

                    for (smaller_form_num, smaller_form) in scheme.into_iter().enumerate() {
                        if smaller_form_num >= form_num || (smaller_form.params().0 as u32) < dir_bit_count {
                            continue;
                        }

                        let sml = re_encode(full_label, scheme, Some(smaller_form_num)).expect("bad test");
                        assert_eq!(
                            re_encode(sml, scheme, Some(biggest_form_num)),
                            Ok(full_label)
                        );

                        assert_eq!(re_encode(sml, scheme, Some(form_num)), Ok(med));
                        assert_eq!(re_encode(med, scheme, Some(smaller_form_num)), Ok(sml));
                    }
                }
            }
        }

        for scheme in schemes::all() {
            if *scheme == *schemes::V358 {
                continue;
            }

            test_scheme(scheme);
        }
    }

    #[test]
    fn test_reencode_358() {
        for i in 1..256 {
            let (form_num, label): (usize, RoutingLabel<u64>) = match director_bit_length(i) {
                1..=3 => (0, RoutingLabel::try_new((1 << 4) | (i << 1) | 1).expect("bad test data")),
                4 | 5 => (1, RoutingLabel::try_new((1 << 7) | (i << 2) | (0b10)).expect("bad test data")),
                6..=8 => (2, RoutingLabel::try_new((1 << 10) | (i << 2)).expect("bad test data")),
                _ => panic!(),
            };

            if form_num < 2 {
                let label2 = re_encode(label, &schemes::V358, Some(2)).expect("bad test");
                assert_eq!(
                    re_encode(label2, &schemes::V358, Some(form_num)),
                    Ok(label)
                );
                assert_eq!(re_encode(label2, &schemes::V358, None), Ok(label));

                if form_num < 1 {
                    let label1 = re_encode(label, &schemes::V358, Some(1)).expect("bad test");
                    assert_eq!(
                        re_encode(label2, &schemes::V358, Some(1)),
                        Ok(label1)
                    );
                    assert_eq!(
                        re_encode(label1, &schemes::V358, Some(2)),
                        Ok(label2)
                    );
                    assert_eq!(re_encode(label1, &schemes::V358, Some(0)), Ok(label));
                    assert_eq!(re_encode(label1, &schemes::V358, None), Ok(label));
                }
            }
            //TODO what if form_num >= 2? Need some assert on it.
        }
    }

    #[test]
    fn test_routes_through() {
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0015")),
            true
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.001b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.0000.0000.0015")
            ),
            true
        );
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0013")),
            false
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.001b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.0000.0000.0013")
            ),
            false
        );
        // lt 2 checks
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0001")),
            true
        );
        // checking other edge cases
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.001b.0535.10e5")),
            true
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.001b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.001b.0535.10e5")
            ),
            true
        );
        assert_eq!(
            routes_through(l("0000.0000.0000.0001"), l("0000.0000.0000.0001")),
            true
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.0000.0000.0001"),
                l128("0000.0000.0000.0000.0000.0000.0000.0001")
            ),
            true
        );
        assert_eq!(
            routes_through(l("ffff.ffff.ffff.ffff"), l("ffff.ffff.ffff.fffe")),
            false
        );
        assert_eq!(
            routes_through(l("ffff.ffff.ffff.ffff"), l("0000.0000.0000.0001")),
            true
        );
        assert_eq!(
            routes_through(
                l128("ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff"),
                l128("0000.0000.0000.0000.0000.0000.0000.0001")
            ),
            true
        );
        assert_eq!(
            routes_through(l("ffff.ffff.ffff.ffff"), l("0000.0000.0000.0002")),
            false
        );
        assert_eq!(
            routes_through(l("0000.0000.0035.0e00"), l("0000.001b.0535.10e5")),
            false
        );
        assert_eq!(
            routes_through(l("0000.000b.0535.10e5"), l("0000.001b.0535.10e5")),
            false
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.000b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.001b.0535.10e5")
            ),
            false
        );
    }

    #[test]
    fn test_unsplice() {
        assert_eq!(
            unsplice(l("0000.0000.0000.0153"), l("0000.0000.0000.0013")),
            Ok(l("0000.0000.0000.0015"))
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0153"),
                l128("0000.0000.0000.0000.0000.0000.0000.0013")
            ),
            Ok(l128("0000.0000.0000.0000.0000.0000.0000.0015"))
        );
        assert_eq!(
            unsplice(l("0000.0000.0000.0153"), l("0000.0000.0000.0001")),
            Ok(l("0000.0000.0000.0153"))
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0153"),
                l128("0000.0000.0000.0000.0000.0000.0000.0001")
            ),
            Ok(l128("0000.0000.0000.0000.0000.0000.0000.0153"))
        );
        assert_eq!(
            unsplice(l("0000.0000.0000.0153"), l("0000.0000.0000.0153")),
            Ok(l("0000.0000.0000.0001"))
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0153"),
                l128("0000.0000.0000.0000.0000.0000.0000.0153")
            ),
            Ok(l128("0000.0000.0000.0000.0000.0000.0000.0001"))
        );
        assert_eq!(
            unsplice(l("0000.0000.0000.0001"), l("0000.0000.0000.0001")),
            Ok(l("0000.0000.0000.0001"))
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0001"),
                l128("0000.0000.0000.0000.0000.0000.0000.0001")
            ),
            Ok(l128("0000.0000.0000.0000.0000.0000.0000.0001"))
        );
        assert_eq!(
            unsplice(l("0000.000b.0535.10e5"), l("0000.001b.0535.10e5")),
            Err(SpliceError::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.000b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.001b.0535.10e5")
            ),
            Err(SpliceError::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0013"),
                l128("0000.0000.0000.0000.0000.0000.0000.0153")
            ),
            Err(SpliceError::CannotUnsplice)
        );
        assert_eq!(
            unsplice(l("ffff.ffff.ffff.ffff"), l("0000.0000.0000.0002")),
            Err(SpliceError::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff"),
                l128("0000.0000.0000.0000.0000.0000.0000.0002")
            ),
            Err(SpliceError::CannotUnsplice)
        );
        assert_eq!(
            unsplice(l("0000.0000.0000.0101"), l("0000.0000.0000.0110")),
            Err(SpliceError::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0101"),
                l128("0000.0000.0000.0000.0000.0000.0000.0110")
            ),
            Err(SpliceError::CannotUnsplice)
        );
        let label64_array = vec![
            l("0000.0000.0000.0015"),
            l("0000.0000.0000.008e"),
            l("0000.0000.0000.00a2"),
            l("0000.0000.0000.001d"),
            l("0000.0000.0000.0414"),
            l("0000.0000.0000.001b"),
        ];
        let mut test64_val = l("0000.001b.0535.10e5");
        for label in label64_array {
            test64_val = unsplice(test64_val, label).expect("failed to unsplice");
        }
        assert_eq!(test64_val, l("0000.0000.0000.0001"));

        let label128_array = vec![
            l128("0000.0000.0000.0000.0000.0000.0000.0015"),
            l128("0000.0000.0000.0000.0000.0000.0000.008e"),
            l128("0000.0000.0000.0000.0000.0000.0000.00a2"),
            l128("0000.0000.0000.0000.0000.0000.0000.001d"),
            l128("0000.0000.0000.0000.0000.0000.0000.0414"),
            l128("0000.0000.0000.0000.0000.0000.0000.001b"),
        ];
        let mut test128_val = l128("0000.0000.0000.0000.0000.001b.0535.10e5");
        for label in label128_array {
            test128_val = unsplice(test128_val, label).expect("failed to unsplice");
        }
        assert_eq!(test128_val, l128("0000.0000.0000.0000.0000.0000.0000.0001"));
    }

    #[test]
    fn test_build_label() {
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.009e"),
                    lopt("0000.0000.0000.008e"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.00a2"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.001b"),
                    lopt("0000.0000.0000.001d"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.00ee"),
                    lopt("0000.0000.0000.001b"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0019"),
                    lopt("0000.0000.0000.001b"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Ok((
                l("0000.0003.64b5.10e5"),
                vec![
                    l("0000.0000.0000.0015"),
                    l("0000.0000.0000.008e"),
                    l("0000.0000.0000.00a2"),
                    l("0000.0000.0000.001d"),
                    l("0000.0000.0000.0092"),
                    l("0000.0000.0000.001b")
                ]
            ))
        );
        assert_eq!(
            build_label(&[PathHop::new(
                lopt("0000.0000.0000.0013"),
                lopt("0000.0000.0000.0000"),
                &schemes::V358,
            )]),
            Err(SpliceError::NotEnoughArguments)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Ok((l("0000.0000.0000.0015"), vec![l("0000.0000.0000.0015")]))
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Err(SpliceError::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Err(SpliceError::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0001"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Err(SpliceError::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0001"),
                    &schemes::V358,
                ),
            ]),
            Err(SpliceError::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.008e"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Err(SpliceError::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.009e"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Err(SpliceError::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.009e"),
                    lopt("0000.0000.0000.008e"),
                    &schemes::V358,
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Ok((
                splice(&[l("0000.0000.0000.008e"), l("0000.0000.0000.0015")]).expect("failed to splice"),
                vec![l("0000.0000.0000.0015"), l("0000.0000.0000.008e")]
            ))
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0000"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0015"),
                    &schemes::V358,
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.009e"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.008e"),
                    &schemes::V358,
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0013"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.00a2"),
                    &schemes::V358,
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001b"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001d"),
                    &schemes::V358,
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.00ee"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001b"),
                    &schemes::V358,
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0019"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001b"),
                    &schemes::V358,
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0013"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0000"),
                    &schemes::V358,
                ),
            ]),
            Ok((
                l128("0000.0000.0000.0000.0000.0003.64b5.10e5"),
                vec![
                    l128("0000.0000.0000.0000.0000.0000.0000.0015"),
                    l128("0000.0000.0000.0000.0000.0000.0000.008e"),
                    l128("0000.0000.0000.0000.0000.0000.0000.00a2"),
                    l128("0000.0000.0000.0000.0000.0000.0000.001d"),
                    l128("0000.0000.0000.0000.0000.0000.0000.0092"),
                    l128("0000.0000.0000.0000.0000.0000.0000.001b")
                ]
            ))
        );
    }

    #[test]
    fn test_is_one_hop() {
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0013"), &schemes::V358),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0015"), &schemes::V358),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0153"), &schemes::V358),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0001"), &schemes::V358),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0002"), &schemes::V358),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0096"), &schemes::V358),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0400"), &schemes::V358),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0115"), &schemes::V358),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0166"), &schemes::V358),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.1400"), &schemes::V358),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0001"), &schemes::V48),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0021"), &schemes::V48),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0023"), &schemes::V48),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0012"), &schemes::V48),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0220"), &schemes::V48),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0210"), &schemes::V48),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0110"), &schemes::V48),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(
                l("0000.0000.0000.1113"),
                &encoding_scheme(&[
                    encoding_form(5, 2, 2),
                    encoding_form(8, 2, 0),
                ])
            ),
            Err(SpliceError::CannotFindForm)
        );
    }
}
