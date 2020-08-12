//! Routing label splice/unsplice routines.

use std::error;
use std::fmt;

use cjdns_entities::{EncodingScheme, EncodingSchemeForm, LabelBits, PathHop, RoutingLabel, SCHEMES};

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    LabelTooLong,
    NotEnoughArguments,
    BadArgument,
    CannotUnsplice,
    CannotFindForm,
    CannotReencode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::LabelTooLong => write!(f, "Label is too long"),
            Error::NotEnoughArguments => write!(f, "Not enough arguments"),
            Error::BadArgument => write!(f, "Bad argument"),
            Error::CannotUnsplice => write!(f, "Can't unsplice"),
            Error::CannotFindForm => write!(f, "Can't detect form"),
            Error::CannotReencode => write!(f, "Can't re-encode"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// This function takes one or more `labels` and splices them to create a resulting label.
pub fn splice<L: LabelBits>(labels: &[RoutingLabel<L>]) -> Result<RoutingLabel<L>> {
    if labels.len() < 2 {
        return Err(Error::NotEnoughArguments);
    }

    let mut result_bits = labels[0].bits();
    assert!(result_bits.highest_set_bit().is_some()); // because every RoutingLabel is always non-zero

    for addon in &labels[1..] {
        let addon_bitlen = addon.highest_set_bit();
        let result_hsb = result_bits.highest_set_bit().expect("intermediate result is zero");
        if result_hsb + addon_bitlen > L::MAX_PAYLOAD_BITS - 1 {
            return Err(Error::LabelTooLong);
        }

        result_bits = ((result_bits ^ L::ONE) << addon_bitlen) ^ addon.bits();
    }

    RoutingLabel::try_new(result_bits).ok_or(()).map_err(|_| unreachable!("result_bits is zero"))
}

/// Get the encoding form used for the first director of the `label`.
pub fn get_encoding_form<L: LabelBits>(
    label: RoutingLabel<L>,
    scheme: &EncodingScheme,
) -> Result<(EncodingSchemeForm, usize)> {
    for (i, form) in scheme.forms().iter().enumerate() {
        if 0 == form.prefix_len {
            return Ok((*form, i));
        }

        if form.prefix_len > 32 {
            continue;
        }

        let mask = if form.prefix_len == 32 {
            0xFFFFFFFFu32
        } else {
            (1u32 << (form.prefix_len as u32)) - 1u32
        };
        if label.bits() & mask.into() == form.prefix.into() {
            return Ok((*form, i));
        }
    }

    Err(Error::CannotFindForm)
}

/// Extracts a director stripping the encoding.
#[inline]
fn get_director<L: LabelBits>(label: RoutingLabel<L>, form: EncodingSchemeForm) -> L {
    let padding = L::BIT_SIZE - form.bit_count as u32 - form.prefix_len as u32;
    (label.bits() << padding) >> (padding + form.prefix_len as u32)
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

/// Detects canonical (shortest) form which has enough space to hold `dir`.
fn find_shortest_form<L: LabelBits>(dir: L, scheme: &EncodingScheme) -> Result<EncodingSchemeForm> {
    let dir_bits = director_bit_length(dir);

    scheme
        .forms()
        .iter()
        .filter(|&form| (form.bit_count as u32) >= dir_bits)
        .min_by_key(|&form| form.bit_count)
        .map(|&form| form)
        .ok_or(Error::CannotFindForm)
}

/// Re-encode a `label` to the encoding form specified by `desired_form_num`
/// (or canonical if `None`).
pub fn re_encode<L: LabelBits>(
    label: RoutingLabel<L>,
    scheme: &EncodingScheme,
    desired_form_num: Option<usize>,
) -> Result<RoutingLabel<L>> {
    let (form, _) = get_encoding_form(label, scheme)?;
    let mut dir = get_director(label, form);

    let mut desired_form = if let Some(num) = desired_form_num {
        if num >= scheme.forms().len() {
            return Err(Error::BadArgument);
        }
        scheme.forms()[num]
    } else {
        find_shortest_form(dir, scheme)?
    };

    if scheme == &SCHEMES["v358"] {
        // Special magic for SCHEME_358 legacy.
        fn is_358_zero_form(f: EncodingSchemeForm) -> bool {
            f == SCHEMES["v358"].forms()[0]
        }

        if is_358_zero_form(desired_form) && dir == 0b111_u32.into() {
            desired_form = SCHEMES["v358"].forms()[1];
        }

        if is_358_zero_form(form) {
            if dir == L::ZERO {
                return Err(Error::CannotReencode);
            }
            dir = dir - L::ONE;
        }
        if is_358_zero_form(desired_form) {
            dir = dir + L::ONE;
        }
    }

    // Construct result: [bits before extracted dir][padded dir][desired form prefix]
    let mut result_bits = label.bits() >> (form.bit_count as u32 + form.prefix_len as u32);

    // check for overflow
    let rest_bitlen = match result_bits.highest_set_bit() {
        None => 0,
        Some(len) => len + 1,
    };
    let used_bits = rest_bitlen + desired_form.bit_count as u32 + desired_form.prefix_len as u32;
    if used_bits > L::MAX_PAYLOAD_BITS {
        return Err(Error::LabelTooLong);
    }

    result_bits = (result_bits << (desired_form.bit_count as u32)) | dir;
    result_bits = (result_bits << (desired_form.prefix_len as u32)) | desired_form.prefix.into();

    RoutingLabel::try_new(result_bits).ok_or(()).map_err(|_| unreachable!("result_bits is zero"))
}

/// Tests if a `label` contains only one hop.
pub fn is_one_hop<L: LabelBits>(label: RoutingLabel<L>, encoding_scheme: &EncodingScheme) -> Result<bool> {
    let (label_form, _) = get_encoding_form(label, encoding_scheme)?;
    let form_bits = (label_form.bit_count + label_form.prefix_len) as u32;
    Ok(label.highest_set_bit() == form_bits)
}

/// This will construct a label using an array representation of a path (`path_hops`), if any label along the `path_hops` needs to be re-encoded, it will be.
pub fn build_label<L: LabelBits>(path_hops: &[PathHop<L>]) -> Result<(RoutingLabel<L>, Vec<RoutingLabel<L>>)> {
    if path_hops.len() < 2 {
        return Err(Error::NotEnoughArguments);
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
    let first_hop_label_n = first_hop.label_n.ok_or(Error::BadArgument)?; // must be Some
    let _last_hop_label_p = last_hop.label_p.ok_or(Error::BadArgument)?; // must be Some
    first_hop.label_p.map_or(Ok(()), |_| Err(Error::BadArgument))?; // must be None
    last_hop.label_n.map_or(Ok(()), |_| Err(Error::BadArgument))?; // must be None

    let mut ret_path = Vec::with_capacity(mid_hops.len() + 1);
    ret_path.push(first_hop_label_n);

    // Iterate over hops except for first and last
    for hop in mid_hops {
        if let (Some(label_p), Some(mut label_n)) = (hop.label_p, hop.label_n) {
            let (form_label_p, form_idx) = get_encoding_form(label_p, hop.encoding_scheme)?;
            let (form_label_n, _) = get_encoding_form(label_n, hop.encoding_scheme)?;
            if form_label_p.bit_count + form_label_p.prefix_len > form_label_n.bit_count + form_label_n.prefix_len {
                label_n = re_encode(label_n, hop.encoding_scheme, Some(form_idx))?;
            }

            ret_path.push(label_n);
        } else {
            return Err(Error::BadArgument);
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

/// This will return `Ok(true)` if the node at the end of the route given by `mid_path` is a hop along the path given by `destination`
pub fn routes_through<L: LabelBits>(destination: RoutingLabel<L>, mid_path: RoutingLabel<L>) -> bool {
    let (dest_highest_set_bit, mid_path_highest_set_bit) = (destination.highest_set_bit(), mid_path.highest_set_bit());
    if dest_highest_set_bit < mid_path_highest_set_bit {
        return false;
    }
    let mask = (L::ONE << mid_path_highest_set_bit) - L::ONE;
    destination.bits() & mask == mid_path.bits() & mask
}

/// Convert a full path to a representation which a node along that path can use
pub fn unsplice<L: LabelBits>(destination: RoutingLabel<L>, mid_path: RoutingLabel<L>) -> Result<RoutingLabel<L>> {
    if !(routes_through(destination, mid_path)) {
        return Err(Error::CannotUnsplice);
    }

    RoutingLabel::try_new(destination.bits() >> mid_path.highest_set_bit()).ok_or(()).map_err(|_| unreachable!("highest_set_bit() is broken"))
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use cjdns_entities::{RoutingLabel, SCHEMES};

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

    #[test]
    fn test_splice() {
        assert_eq!(splice::<u64>(&[]), Err(Error::NotEnoughArguments));
        assert_eq!(
            splice(&[l("0000.0000.0000.0015")]),
            Err(Error::NotEnoughArguments)
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
            Err(Error::LabelTooLong)
        );
        assert_eq!(
            splice(&[
                l128("0400.0000.0000.0000.0000.0000.0000.1111"),
                l128("0000.0000.0000.0000.0000.0000.0000.0005")
            ]),
            Err(Error::LabelTooLong)
        );
    }

    #[test]
    fn test_get_encoding_form() {
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &SCHEMES["f8"]),
            Ok((
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 0,
                    prefix: 0,
                },
                0
            ))
        );

        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1110"), &SCHEMES["v358"]),
            Ok((
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 2,
                    prefix: 0,
                },
                2
            ))
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &SCHEMES["v358"]),
            Ok((
                EncodingSchemeForm {
                    bit_count: 3,
                    prefix_len: 1,
                    prefix: 1,
                },
                0
            ))
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1112"), &SCHEMES["v358"]),
            Ok((
                EncodingSchemeForm {
                    bit_count: 5,
                    prefix_len: 2,
                    prefix: 2,
                },
                1
            ))
        );

        assert_eq!(
            get_encoding_form(l("0000.0000.0000.0013"), &SCHEMES["v358"]),
            Ok((
                EncodingSchemeForm {
                    bit_count: 3,
                    prefix_len: 1,
                    prefix: 0b01,
                },
                0
            ))
        );

        assert!(get_encoding_form(
            l("0000.0000.0000.1113"),
            &EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 5,
                    prefix_len: 2,
                    prefix: 0b10,
                },
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 2,
                    prefix: 0b00,
                },
            ])
        )
        .is_err());
    }

    #[test]
    fn test_find_shortest_form() {
        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0002").bits(), &SCHEMES["f4"]),
            Ok(EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 0,
                prefix: 0,
            })
        );
        assert!(find_shortest_form(l("0000.0000.0000.0010").bits(), &SCHEMES["f4"]).is_err());

        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0002").bits(), &SCHEMES["v48"]),
            Ok(EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 1,
                prefix: 0b01,
            })
        );
        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0010").bits(), &SCHEMES["v48"]),
            Ok(EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 1,
                prefix: 0b00,
            })
        );
        assert!(find_shortest_form(l("0000.0000.0000.0100").bits(), &SCHEMES["v48"]).is_err());

        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0015").bits(), &SCHEMES["v358"]),
            Ok(EncodingSchemeForm {
                bit_count: 5,
                prefix_len: 2,
                prefix: 0b10,
            })
        );
    }

    #[test]
    fn test_reencode_basic() {
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(2)),
            Ok(l("0000.0000.0000.0404"))
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(1)),
            Ok(l("0000.0000.0000.0086"))
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(0)),
            Ok(l("0000.0000.0000.0015"))
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0404"), &SCHEMES["v358"], None),
            Ok(l("0000.0000.0000.0015"))
        );

        assert!(re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(3)).is_err());
        assert!(re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(4)).is_err());

        assert!(re_encode(
            l("0000.0000.0000.1113"),
            &EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 5,
                    prefix_len: 2,
                    prefix: 0b10,
                },
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 2,
                    prefix: 0b00,
                },
            ]),
            None
        )
        .is_err());

        assert_eq!(
            re_encode(l("0040.0000.0000.0067"), &SCHEMES["v48"], Some(1)),
            Ok(l("0400.0000.0000.0606"))
        );
        assert!(re_encode(l("0400.0000.0000.0067"), &SCHEMES["v48"], Some(1)).is_err());
    }

    #[test]
    fn test_reencode_big() {
        fn test_scheme(scheme: &EncodingScheme) {
            let biggest_form = *(scheme.forms().last().expect("bad test"));
            let biggest_form_num = scheme.forms().len() - 1;
            let max = ((1u64 << (biggest_form.bit_count as u64)) - 1) as u32;

            for i in 0..max {
                let full_label_bits = (1_u64 << (biggest_form.bit_count as u32 + biggest_form.prefix_len as u32))
                    | ((i as u64) << (biggest_form.prefix_len as u32))
                    | (biggest_form.prefix as u64);
                let full_label = RoutingLabel::try_new(full_label_bits).expect("bad test data");

                let dir_bit_count = director_bit_length(i as u64);
                for (form_num, form) in scheme.into_iter().enumerate() {
                    if (form.bit_count as u32) < dir_bit_count {
                        continue;
                    }

                    let med = re_encode(full_label, scheme, Some(form_num)).expect("bad test");
                    assert_eq!(
                        re_encode(med, scheme, Some(biggest_form_num)),
                        Ok(full_label)
                    );

                    for (smaller_form_num, smaller_form) in scheme.into_iter().enumerate() {
                        if smaller_form_num >= form_num || (smaller_form.bit_count as u32) < dir_bit_count {
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

        for (scheme_name, scheme) in SCHEMES.iter() {
            if *scheme_name == "v358" {
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
                let label2 = re_encode(label, &SCHEMES["v358"], Some(2)).expect("bad test");
                assert_eq!(
                    re_encode(label2, &SCHEMES["v358"], Some(form_num)),
                    Ok(label)
                );
                assert_eq!(re_encode(label2, &SCHEMES["v358"], None), Ok(label));

                if form_num < 1 {
                    let label1 = re_encode(label, &SCHEMES["v358"], Some(1)).expect("bad test");
                    assert_eq!(
                        re_encode(label2, &SCHEMES["v358"], Some(1)),
                        Ok(label1)
                    );
                    assert_eq!(
                        re_encode(label1, &SCHEMES["v358"], Some(2)),
                        Ok(label2)
                    );
                    assert_eq!(re_encode(label1, &SCHEMES["v358"], Some(0)), Ok(label));
                    assert_eq!(re_encode(label1, &SCHEMES["v358"], None), Ok(label));
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
            Err(Error::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.000b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.001b.0535.10e5")
            ),
            Err(Error::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0013"),
                l128("0000.0000.0000.0000.0000.0000.0000.0153")
            ),
            Err(Error::CannotUnsplice)
        );
        assert_eq!(
            unsplice(l("ffff.ffff.ffff.ffff"), l("0000.0000.0000.0002")),
            Err(Error::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff"),
                l128("0000.0000.0000.0000.0000.0000.0000.0002")
            ),
            Err(Error::CannotUnsplice)
        );
        assert_eq!(
            unsplice(l("0000.0000.0000.0101"), l("0000.0000.0000.0110")),
            Err(Error::CannotUnsplice)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.0000.0000.0101"),
                l128("0000.0000.0000.0000.0000.0000.0000.0110")
            ),
            Err(Error::CannotUnsplice)
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
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.009e"),
                    lopt("0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.00a2"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.001b"),
                    lopt("0000.0000.0000.001d"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.00ee"),
                    lopt("0000.0000.0000.001b"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0019"),
                    lopt("0000.0000.0000.001b"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
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
                &SCHEMES["v358"]
            )]),
            Err(Error::NotEnoughArguments)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Ok((l("0000.0000.0000.0015"), vec![l("0000.0000.0000.0015")]))
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0001"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0001"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.009e"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    lopt("0000.0000.0000.0000"),
                    lopt("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.009e"),
                    lopt("0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    lopt("0000.0000.0000.0013"),
                    lopt("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
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
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.009e"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0013"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.00a2"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001b"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001d"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.00ee"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001b"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0019"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.001b"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0013"),
                    l128opt("0000.0000.0000.0000.0000.0000.0000.0000"),
                    &SCHEMES["v358"]
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
            is_one_hop(l("0000.0000.0000.0013"), &SCHEMES["v358"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0015"), &SCHEMES["v358"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0153"), &SCHEMES["v358"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0001"), &SCHEMES["v358"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0002"), &SCHEMES["v358"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0096"), &SCHEMES["v358"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0400"), &SCHEMES["v358"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0115"), &SCHEMES["v358"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0166"), &SCHEMES["v358"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.1400"), &SCHEMES["v358"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0001"), &SCHEMES["v48"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0021"), &SCHEMES["v48"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0023"), &SCHEMES["v48"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0012"), &SCHEMES["v48"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0220"), &SCHEMES["v48"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0210"), &SCHEMES["v48"]),
            Ok(true)
        );
        assert_eq!(
            is_one_hop(l("0000.0000.0000.0110"), &SCHEMES["v48"]),
            Ok(false)
        );
        assert_eq!(
            is_one_hop(
                l("0000.0000.0000.1113"),
                &EncodingScheme::new(&[
                    EncodingSchemeForm {
                        bit_count: 5,
                        prefix_len: 2,
                        prefix: 0b10,
                    },
                    EncodingSchemeForm {
                        bit_count: 8,
                        prefix_len: 2,
                        prefix: 0b00,
                    },
                ])
            ),
            Err(Error::CannotFindForm)
        );
        assert_eq!(
            is_one_hop(
                l("0000.0000.0000.0200"),
                &EncodingScheme::new(&[EncodingSchemeForm {
                    bit_count: 4,
                    prefix_len: 1,
                    prefix: 0b01,
                },])
            ),
            Err(Error::CannotFindForm)
        );
    }
}
