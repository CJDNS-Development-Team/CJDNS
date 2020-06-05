use std::error;
use std::fmt;

use cjdns_entities::{EncodingScheme, EncodingSchemeForm, LabelT};

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug, PartialEq)]
pub enum Error {
    LabelTooLong,
    ZeroLabel,
    NotEnoughArguments,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::LabelTooLong => write!(f, "Label is too long"),
            Error::ZeroLabel => write!(f, "Label is zero"),
            Error::NotEnoughArguments => write!(f, "Not enough arguments"),
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
) -> Option<EncodingSchemeForm> {
    for form in scheme.forms() {
        if 0 == form.prefix_len {
            return Some(*form);
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
            return Some(*form);
        }
    }

    None
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
            Some(EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 0,
                prefix: 0,
            })
        );

        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1110"), &SCHEMES["v358"]),
            Some(EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 2,
                prefix: 0,
            })
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1111"), &SCHEMES["v358"]),
            Some(EncodingSchemeForm {
                bit_count: 3,
                prefix_len: 1,
                prefix: 1,
            })
        );
        assert_eq!(
            get_encoding_form(l("0000.0000.0000.1112"), &SCHEMES["v358"]),
            Some(EncodingSchemeForm {
                bit_count: 5,
                prefix_len: 2,
                prefix: 2,
            })
        );

        assert_eq!(
            get_encoding_form(
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
            None
        );
    }
}
