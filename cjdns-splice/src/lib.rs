use std::error;
use std::fmt;

use cjdns_entities::{EncodingScheme, EncodingSchemeForm, LabelT, PathHop, SCHEMES};

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug, PartialEq)]
pub enum Error {
    LabelTooLong,
    ZeroLabel,
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
            Error::ZeroLabel => write!(f, "Label is zero"),
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
pub fn splice<L: LabelT>(labels: &[L]) -> Result<L> {
    if labels.len() < 2 {
        return Err(Error::NotEnoughArguments);
    }

    let mut result = labels[0];
    if result.highest_set_bit().is_none() {
        return Err(Error::ZeroLabel);
    }

    for addon in &labels[1..] {
        match addon.highest_set_bit() {
            None => return Err(Error::ZeroLabel),

            Some(addon_bitlen) => {
                if result.highest_set_bit().unwrap() + addon_bitlen > L::max_bit_size() - 1 {
                    return Err(Error::LabelTooLong);
                }

                result = ((result ^ L::from_u32(1u32)) << addon_bitlen) ^ *addon;
            }
        }
    }

    Ok(result)
}

/// Get the encoding form used for the first director of the `label`.
pub fn get_encoding_form<L: LabelT>(
    label: L,
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
        if label & L::from_u32(mask) == L::from_u32(form.prefix) {
            return Ok((*form, i));
        }
    }

    Err(Error::CannotFindForm)
}

/// Extracts a director stripping the encoding.
#[inline]
fn get_director<L: LabelT>(label: L, form: EncodingSchemeForm) -> L {
    let padding = L::type_bit_size() - form.bit_count as u32 - form.prefix_len as u32;
    (label << padding) >> (padding + form.prefix_len as u32)
}

/// Bit length of a director (not a label, e.g. without self-route).
#[inline]
fn director_bit_length<L: LabelT>(dir: L) -> u32 {
    dir.highest_set_bit().unwrap_or(0u32) + 1u32
}

/// Detects canonical (shortest) form which has enough space to hold `dir`.
fn find_shortest_form<L: LabelT>(dir: L, scheme: &EncodingScheme) -> Result<EncodingSchemeForm> {
    let dir_bits = director_bit_length(dir);
    let mut best_form: Option<EncodingSchemeForm> = None;

    for form in scheme {
        if (form.bit_count as u32) < dir_bits {
            continue;
        }
        if best_form.is_none() || best_form.unwrap().bit_count > form.bit_count {
            best_form = Some(*form)
        }
    }

    if best_form.is_none() {
        Err(Error::CannotFindForm)
    } else {
        Ok(best_form.unwrap())
    }
}

/// Re-encode a `label` to the encoding form specified by `desired_form_num`
/// (or canonical if `None`).
pub fn re_encode<L: LabelT>(
    label: L,
    scheme: &EncodingScheme,
    desired_form_num: Option<usize>,
) -> Result<L> {
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

        if is_358_zero_form(desired_form) && dir == L::from_u32(0b111) {
            desired_form = SCHEMES["v358"].forms()[1];
        }

        if is_358_zero_form(form) {
            if dir == L::from_u32(0) {
                return Err(Error::CannotReencode);
            }
            dir = dir - 1u32;
        }
        if is_358_zero_form(desired_form) {
            dir = dir + 1u32;
        }
    }

    // Construct result: [bits before extracted dir][padded dir][desired form prefix]
    let mut result = label >> (form.bit_count as u32 + form.prefix_len as u32);

    // check for overflow
    let rest_bitlen = match result.highest_set_bit() {
        None => 0,
        Some(len) => len + 1,
    };
    if rest_bitlen + desired_form.bit_count as u32 + desired_form.prefix_len as u32
        > L::max_bit_size()
    {
        return Err(Error::LabelTooLong);
    }

    result = (result << (desired_form.bit_count as u32)) | dir;
    result = (result << (desired_form.prefix_len as u32)) | L::from_u32(desired_form.prefix);

    Ok(result)
}

/// Tests if a `label` contains only one hop.
pub fn is_one_hop<L: LabelT>(label: L, encoding_scheme: &EncodingScheme) -> Result<bool> {
    if label.highest_set_bit().is_none() {
        return Err(Error::ZeroLabel);
    }

    let (label_form, _) = get_encoding_form(label, encoding_scheme)?;
    let form_bits = label_form.bit_count + label_form.prefix_len;

    Ok(label.highest_set_bit().unwrap() == form_bits as u32)
}

/// This will construct a label using an array representation of a path (`path_hops`), if any label along the `path_hops` needs to be re-encoded, it will be.
pub fn build_label<L: LabelT>(path_hops: &[PathHop<L>]) -> Result<(L, Vec<L>)> {
    if path_hops.len() < 2 {
        return Err(Error::NotEnoughArguments);
    }

    if path_hops.first().unwrap().label_n.is_none()
        || path_hops.last().unwrap().label_p.is_none()
        || path_hops.first().unwrap().label_p.is_some()
        || path_hops.last().unwrap().label_n.is_some()
    {
        return Err(Error::BadArgument);
    }

    let mut ret_path = Vec::with_capacity(path_hops.len() - 1);
    ret_path.push(path_hops.first().unwrap().label_n.unwrap());

    let hops_to_iter_over = &path_hops[1..path_hops.len() - 1];

    // Iterate over hops except for first and last
    for hop in hops_to_iter_over {
        if hop.label_n.is_none() || hop.label_p.is_none() {
            return Err(Error::BadArgument);
        }

        // alias
        let label_p = hop.label_p.unwrap();
        let mut label_n = hop.label_n.unwrap();

        let (form_label_p, form_idx) = get_encoding_form(label_p, hop.encoding_scheme)?;
        let (form_label_n, _) = get_encoding_form(label_n, hop.encoding_scheme)?;
        if form_label_p.bit_count + form_label_p.prefix_len
            > form_label_n.bit_count + form_label_n.prefix_len
        {
            label_n = re_encode(label_n, hop.encoding_scheme, Some(form_idx))?;
        }

        ret_path.push(label_n);
    }

    let ret_label = if ret_path.len() > 1 {
        let mut y = ret_path.clone();
        y.reverse();
        splice(&y)?
    } else {
        *ret_path.first().unwrap()
    };

    Ok((ret_label, ret_path))
}

/// This will return `Ok(true)` if the node at the end of the route given by `mid_path` is a hop along the path given by `destination`
pub fn routes_through<L: LabelT>(destination: L, mid_path: L) -> Result<bool> {
    if destination.highest_set_bit().is_none() || mid_path.highest_set_bit().is_none() {
        return Err(Error::ZeroLabel);
    }

    if destination.highest_set_bit().unwrap() < mid_path.highest_set_bit().unwrap() {
        return Ok(false);
    }

    let mask = (L::from_u32(1) << mid_path.highest_set_bit().unwrap()) - 1;
    Ok(destination & mask == mid_path & mask)
}

/// Convert a full path to a representation which a node along that path can use
pub fn unsplice<L: LabelT>(destination: L, mid_path: L) -> Result<L> {
    if !(routes_through(destination, mid_path)?) {
        return Err(Error::CannotUnsplice);
    }

    Ok(destination >> mid_path.highest_set_bit().unwrap())
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use cjdns_entities::{Label, Label128, SCHEMES};

    fn l(v: &str) -> Label {
        Label::try_from(v).unwrap()
    }

    fn l128(v: &str) -> Label128 {
        Label128::try_from(v).unwrap()
    }

    #[test]
    fn test_splice() {
        assert_eq!(splice::<Label>(&[]), Err(Error::NotEnoughArguments));
        assert_eq!(
            splice(&[l("0000.0000.0000.0015")]),
            Err(Error::NotEnoughArguments)
        );
        assert_eq!(
            splice(&[l("0000.0000.0000.0015"), l("0000.0000.0000.0000")]),
            Err(Error::ZeroLabel)
        );
        assert_eq!(
            splice(&[l("0000.0000.0000.0000"), l("0000.0000.0000.0013")]),
            Err(Error::ZeroLabel)
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
            find_shortest_form(l("0000.0000.0000.0002"), &SCHEMES["f4"]).unwrap(),
            EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 0,
                prefix: 0,
            }
        );
        assert!(find_shortest_form(l("0000.0000.0000.0010"), &SCHEMES["f4"]).is_err());

        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0002"), &SCHEMES["v48"]).unwrap(),
            EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 1,
                prefix: 0b01,
            }
        );
        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0010"), &SCHEMES["v48"]).unwrap(),
            EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 1,
                prefix: 0b00,
            }
        );
        assert!(find_shortest_form(l("0000.0000.0000.0100"), &SCHEMES["v48"]).is_err());

        assert_eq!(
            find_shortest_form(l("0000.0000.0000.0015"), &SCHEMES["v358"]).unwrap(),
            EncodingSchemeForm {
                bit_count: 5,
                prefix_len: 2,
                prefix: 0b10,
            }
        );
    }

    #[test]
    fn test_reencode_basic() {
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(2)).unwrap(),
            l("0000.0000.0000.0404")
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(1)).unwrap(),
            l("0000.0000.0000.0086")
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0015"), &SCHEMES["v358"], Some(0)).unwrap(),
            l("0000.0000.0000.0015")
        );
        assert_eq!(
            re_encode(l("0000.0000.0000.0404"), &SCHEMES["v358"], None).unwrap(),
            l("0000.0000.0000.0015")
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
            re_encode(l("0040.0000.0000.0067"), &SCHEMES["v48"], Some(1)).unwrap(),
            l("0400.0000.0000.0606")
        );
        assert!(re_encode(l("0400.0000.0000.0067"), &SCHEMES["v48"], Some(1)).is_err());
    }

    #[test]
    fn test_reencode_big() {
        fn test_scheme(scheme: &EncodingScheme) {
            let biggest_form = *(scheme.forms().last().unwrap());
            let biggest_form_num = scheme.forms().len() - 1;
            let max = ((1u64 << (biggest_form.bit_count as u64)) - 1) as u32;

            for i in 0..max {
                let full_label: Label = (Label::from_u32(1)
                    << (biggest_form.bit_count as u32 + biggest_form.prefix_len as u32))
                    | (Label::from_u32(i) << (biggest_form.prefix_len as u32))
                    | Label::from_u32(biggest_form.prefix);

                let dir_bits = director_bit_length(Label::from_u32(i));
                for (form_num, form) in scheme.into_iter().enumerate() {
                    if (form.bit_count as u32) < dir_bits {
                        continue;
                    }

                    let med = re_encode(full_label, scheme, Some(form_num)).unwrap();
                    assert_eq!(
                        re_encode(med, scheme, Some(biggest_form_num)).unwrap(),
                        full_label
                    );

                    for (smaller_form_num, smaller_form) in scheme.into_iter().enumerate() {
                        if smaller_form_num >= form_num
                            || (smaller_form.bit_count as u32) < dir_bits
                        {
                            continue;
                        }

                        let sml = re_encode(full_label, scheme, Some(smaller_form_num)).unwrap();
                        assert_eq!(
                            re_encode(sml, scheme, Some(biggest_form_num)).unwrap(),
                            full_label
                        );

                        assert_eq!(re_encode(sml, scheme, Some(form_num)).unwrap(), med);
                        assert_eq!(re_encode(med, scheme, Some(smaller_form_num)).unwrap(), sml);
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
        for i in 1u32..256u32 {
            let (form_num, label) = match director_bit_length(Label::from_u32(i)) {
                1..=3 => (
                    0usize,
                    (Label::from_u32(1) << 4u32)
                        | (Label::from_u32(i) << 1u32)
                        | Label::from_u32(1),
                ),
                4 | 5 => (
                    1usize,
                    (Label::from_u32(1) << 7u32)
                        | (Label::from_u32(i) << 2u32)
                        | Label::from_u32(0b10),
                ),
                6..=8 => (
                    2usize,
                    (Label::from_u32(1) << 10u32) | (Label::from_u32(i) << 2u32),
                ),
                _ => panic!(),
            };

            if form_num < 2 {
                let label2 = re_encode(label, &SCHEMES["v358"], Some(2)).unwrap();
                assert_eq!(
                    re_encode(label2, &SCHEMES["v358"], Some(form_num)).unwrap(),
                    label
                );
                assert_eq!(re_encode(label2, &SCHEMES["v358"], None).unwrap(), label);

                if form_num < 1 {
                    let label1 = re_encode(label, &SCHEMES["v358"], Some(1)).unwrap();
                    assert_eq!(
                        re_encode(label2, &SCHEMES["v358"], Some(1)).unwrap(),
                        label1
                    );
                    assert_eq!(
                        re_encode(label1, &SCHEMES["v358"], Some(2)).unwrap(),
                        label2
                    );
                    assert_eq!(re_encode(label1, &SCHEMES["v358"], Some(0)).unwrap(), label);
                    assert_eq!(re_encode(label1, &SCHEMES["v358"], None).unwrap(), label);
                }
            }
        }
    }

    #[test]
    fn test_routes_through() {
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0015")),
            Ok(true)
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.001b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.0000.0000.0015")
            ),
            Ok(true)
        );
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0013")),
            Ok(false)
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.001b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.0000.0000.0013")
            ),
            Ok(false)
        );
        // lt 2 checks
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0001")),
            Ok(true)
        );
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0000")),
            Err(Error::ZeroLabel)
        );
        assert_eq!(
            routes_through(l("0000.0000.0000.0000"), l("0000.001b.0535.10e5")),
            Err(Error::ZeroLabel)
        );
        // checking other edge cases
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.001b.0535.10e5")),
            Ok(true)
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.001b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.001b.0535.10e5")
            ),
            Ok(true)
        );
        assert_eq!(
            routes_through(l("0000.0000.0000.0001"), l("0000.0000.0000.0001")),
            Ok(true)
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.0000.0000.0001"),
                l128("0000.0000.0000.0000.0000.0000.0000.0001")
            ),
            Ok(true)
        );
        assert_eq!(
            routes_through(l("ffff.ffff.ffff.ffff"), l("ffff.ffff.ffff.fffe")),
            Ok(false)
        );
        assert_eq!(
            routes_through(l("ffff.ffff.ffff.ffff"), l("0000.0000.0000.0001")),
            Ok(true)
        );
        assert_eq!(
            routes_through(
                l128("ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff"),
                l128("0000.0000.0000.0000.0000.0000.0000.0001")
            ),
            Ok(true)
        );
        assert_eq!(
            routes_through(l("ffff.ffff.ffff.ffff"), l("0000.0000.0000.0002")),
            Ok(false)
        );
        assert_eq!(
            routes_through(l("0000.0000.0035.0e00"), l("0000.001b.0535.10e5")),
            Ok(false)
        );
        assert_eq!(
            routes_through(l("0000.000b.0535.10e5"), l("0000.001b.0535.10e5")),
            Ok(false)
        );
        assert_eq!(
            routes_through(
                l128("0000.0000.0000.0000.0000.000b.0535.10e5"),
                l128("0000.0000.0000.0000.0000.001b.0535.10e5")
            ),
            Ok(false)
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
        assert_eq!(
            unsplice(l("0000.4500.00a0.0123"), l("0000.0000.0000.0000")),
            Err(Error::ZeroLabel)
        );
        assert_eq!(
            unsplice(
                l128("0000.0000.0000.0000.0000.4500.00a0.0123"),
                l128("0000.0000.0000.0000.0000.0000.0000.0000")
            ),
            Err(Error::ZeroLabel)
        );
        assert_eq!(
            unsplice(l("0000.0000.0000.0000"), l("0000.4500.00a0.0123")),
            Err(Error::ZeroLabel)
        );
    }

    #[test]
    fn test_build_label() {
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.009e"),
                    l("0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.00a2"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.001b"),
                    l("0000.0000.0000.001d"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.00ee"),
                    l("0000.0000.0000.001b"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0019"),
                    l("0000.0000.0000.001b"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
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
                l("0000.0000.0000.0013"),
                l("0000.0000.0000.0000"),
                &SCHEMES["v358"]
            )]),
            Err(Error::NotEnoughArguments)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Ok((l("0000.0000.0000.0015"), vec![l("0000.0000.0000.0015")]))
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0001"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0001"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.009e"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Err(Error::BadArgument)
        );
        assert_eq!(
            build_label(&[
                PathHop::new(
                    l("0000.0000.0000.0000"),
                    l("0000.0000.0000.0015"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.009e"),
                    l("0000.0000.0000.008e"),
                    &SCHEMES["v358"]
                ),
                PathHop::new(
                    l("0000.0000.0000.0013"),
                    l("0000.0000.0000.0000"),
                    &SCHEMES["v358"]
                ),
            ]),
            Ok((
                splice(&[l("0000.0000.0000.008e"), l("0000.0000.0000.0015")]).unwrap(),
                vec![l("0000.0000.0000.0015"), l("0000.0000.0000.008e")]
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
        assert!(is_one_hop(l("0000.0000.0000.0000"), &SCHEMES["v358"]).is_err());
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
