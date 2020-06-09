use std::error;
use std::fmt;

use cjdns_entities::{EncodingScheme, EncodingSchemeForm, LabelT, SCHEMES};

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug, PartialEq)]
pub enum Error {
    LabelTooLong,
    ZeroLabel,
    NotEnoughArguments,
    BadArgument,
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

                result = ((result ^ L::from_u64(1u64)) << addon_bitlen) ^ *addon;
            }
        }
    }

    Ok(result)
}

/// Get the encoding form used for the first director of the `label`.
pub fn get_encoding_form<L: LabelT>(
    label: L,
    scheme: &EncodingScheme,
) -> Result<EncodingSchemeForm> {
    for form in scheme {
        if 0 == form.prefix_len {
            return Ok(*form);
        }

        if form.prefix_len > 32 {
            continue;
        }

        let mask = if form.prefix_len == 32 {
            0xFFFFFFFFu32
        } else {
            (1u32 << (form.prefix_len as u32)) - 1u32
        };
        if label & L::from_u64(mask as u64) == L::from_u64(form.prefix as u64) {
            return Ok(*form);
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

/// Detects canonical (shortest) form which has enough space to hold `dir`.
fn find_shortest_form<L: LabelT>(dir: L, scheme: &EncodingScheme) -> Result<EncodingSchemeForm> {
    let dir_bits = match dir.highest_set_bit() {
        None => return Err(Error::ZeroLabel),
        Some(idx) => idx + 1,
    };
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
    let form = get_encoding_form(label, scheme)?;
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

        if is_358_zero_form(desired_form) && dir == L::from_u64(0b111) {
            desired_form = SCHEMES["v358"].forms()[1];
        }

        if is_358_zero_form(form) {
            if dir == L::from_u64(0) {
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
    result = (result << (desired_form.prefix_len as u32)) | L::from_u64(desired_form.prefix as u64);

    Ok(result)
}

/// This will return `true` if the node at the end of the route given by `mid_path` is a hop along the path given by `destination`
pub fn routes_through<L: LabelT>(destination: L, mid_path: L) -> bool {
    if mid_path > destination {
        return false;
    } else if mid_path < LabelT::from_u64(2) {
        return true;
    }

    let mask = std::u64::MAX >> (64 - mid_path.highest_set_bit().unwrap());
    return (destination.bitand(LabelT::from_u64(mask)))
        == (mid_path.bitand(LabelT::from_u64(mask)));
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use cjdns_entities::{Label, SCHEMES};

    fn l(v: &str) -> Label {
        Label::try_from(v).unwrap()
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
    }

    #[test]
    fn test_splice_long_label() {
        assert_eq!(
            splice(&[l("0200.0000.0000.1111"), l("0000.0000.0000.0005")]),
            Ok(l("0800.0000.0000.4445"))
        );

        assert_eq!(
            splice(&[l("0400.0000.0000.1111"), l("0000.0000.0000.0005")]),
            Err(Error::LabelTooLong)
        );
    }

    #[test]
    fn test_get_encoding_form() {
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &SCHEMES["f8"]),
            Ok(EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 0,
                prefix: 0,
            })
        );

        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1110"), &SCHEMES["v358"]),
            Ok(EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 2,
                prefix: 0,
            })
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &SCHEMES["v358"]),
            Ok(EncodingSchemeForm {
                bit_count: 3,
                prefix_len: 1,
                prefix: 1,
            })
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1112"), &SCHEMES["v358"]),
            Ok(EncodingSchemeForm {
                bit_count: 5,
                prefix_len: 2,
                prefix: 2,
            })
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

        assert!(re_encode(l("0000.0000.0000.0000"), &SCHEMES["v358"], None).is_err());
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
    fn test_routes_through() {
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0015")),
            true
        );
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0013")),
            false
        );
        assert_eq!(
            routes_through(l("0000.001b.0535.10e5"), l("0000.0000.0000.0001")),
            true
        );
        assert_eq!(
            routes_through(l("0000.0000.0000.0001"), l("0000.001b.0535.10e5")),
            false
        );
    }
}
