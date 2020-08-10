//! Routing label encoding scheme.

use std::collections::HashMap;
use std::slice;

/// Encoding scheme.
/// Schemes are comparable for equality, immutable, opaque and iterable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingScheme(Vec<EncodingSchemeForm>);

/// Form used in an encoding scheme.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncodingSchemeForm {
    pub bit_count: u8, // bit_count going first is important for EncodingScheme ordering
    pub prefix_len: u8,
    pub prefix: u32,
}

lazy_static! {
    pub static ref SCHEMES: HashMap<&'static str, EncodingScheme> = {
        let mut m = HashMap::new();

        m.insert(
            "f4",
            EncodingScheme::new(&[EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 0,
                prefix: 0,
            }]),
        );

        m.insert(
            "f8",
            EncodingScheme::new(&[EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 0,
                prefix: 0,
            }]),
        );

        m.insert(
            "v48",
            EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 4,
                    prefix_len: 1,
                    prefix: 0b01,
                },
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 1,
                    prefix: 0b00,
                },
            ]),
        );

        m.insert(
            "v358",
            EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 3,
                    prefix_len: 1,
                    prefix: 0b01,
                },
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
        );

        m.insert(
            "v37",
            EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 3,
                    prefix_len: 1,
                    prefix: 0b01,
                },
                EncodingSchemeForm {
                    bit_count: 7,
                    prefix_len: 1,
                    prefix: 0b00,
                },
            ]),
        );

        m
    };
}

impl EncodingScheme {
    pub fn new(forms: &[EncodingSchemeForm]) -> Self {
        let mut v = forms.to_vec();
        v.sort(); // schemes are comparable; order of forms doesn't matter
        v.dedup();
        Self(v)
    }

    pub fn forms(&self) -> &[EncodingSchemeForm] {
        &self.0
    }
}

impl<'a> IntoIterator for &'a EncodingScheme {
    type Item = &'a EncodingSchemeForm;
    type IntoIter = slice::Iter<'a, EncodingSchemeForm>;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodingScheme, EncodingSchemeForm, SCHEMES};

    fn eform(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
        EncodingSchemeForm {
            bit_count,
            prefix_len,
            prefix,
        }
    }

    #[test]
    fn encoding_scheme_comparison() {
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b00)])
        );
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b00)])
        );
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01)]),
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01), eform(4, 2, 0b00)])
        );

        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b01)])
        );
        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b10)])
        );
        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(3, 2, 0b00)])
        );
        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01)])
        );
    }

    #[test]
    fn encoding_scheme_iteration() {
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01)])
                .into_iter()
                .cloned()
                .collect::<Vec<EncodingSchemeForm>>(),
            vec![eform(4, 2, 0b00), eform(4, 2, 0b01)]
        );
    }

    #[test]
    fn schemes() {
        assert_eq!(SCHEMES["f8"].forms(), &[eform(8, 0, 0)]);

        // smallest to biggest
        assert_eq!(SCHEMES["v358"].forms()[0].bit_count, 3);
        assert_eq!(SCHEMES["v358"].forms()[2].bit_count, 8);
    }
}
