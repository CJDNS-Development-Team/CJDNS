//! Routing label encoding scheme.

use std::slice;

/// Encoding scheme - an iterable list of scheme forms.
///
/// Schemes are comparable for equality, immutable, opaque and iterable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingScheme(Vec<EncodingSchemeForm>);

/// A form of an encoding scheme. Form is used as follows to encode a director:
///
/// ```text
/// [     director     ] [     form.prefix     ]
/// ^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^
/// form.bit_count bits   form.prefix_len bits
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncodingSchemeForm {
    pub bit_count: u8, // bit_count going first is important for EncodingScheme ordering
    pub prefix_len: u8,
    pub prefix: u32,
}

pub mod schemes {
    //! Well-known encoding schemes.

    use super::{EncodingScheme, EncodingSchemeForm};

    lazy_static! {
        /// Fixed-length 4 bit scheme.
        pub static ref F4: EncodingScheme = EncodingScheme::new(&[EncodingSchemeForm {
            bit_count: 4,
            prefix_len: 0,
            prefix: 0,
        }]);

        /// Fixed-length 8 bit scheme.
        pub static ref F8: EncodingScheme = EncodingScheme::new(&[EncodingSchemeForm {
            bit_count: 8,
            prefix_len: 0,
            prefix: 0,
        }]);

        /// Variable-length 4 or 8 bit scheme.
        pub static ref V48: EncodingScheme = EncodingScheme::new(&[
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
        ]);

        /// **Special case scheme.** An encoding scheme consisting of 3, 5 or 8 bit data spaces.
        /// This encoding scheme is special because it encodes strangely (a bug) and thus
        /// conversion from one form to another is non-standard.
        pub static ref V358: EncodingScheme = EncodingScheme::new(&[
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
        ]);

        /// Variable-length 3 or 7 bit scheme.
        pub static ref V37: EncodingScheme = EncodingScheme::new(&[
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
        ]);
    }

    pub fn all() -> impl Iterator<Item=&'static EncodingScheme> + 'static {
        lazy_static! {
            static ref ALL: [EncodingScheme; 5] = [F4.clone(), F8.clone(), V48.clone(), V358.clone(), V37.clone()];
        }
        ALL.iter()
    }
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
    use super::{EncodingScheme, EncodingSchemeForm, schemes};

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
        assert_eq!(schemes::F8.forms(), &[eform(8, 0, 0)]);

        // smallest to biggest
        assert_eq!(schemes::V358.forms()[0].bit_count, 3);
        assert_eq!(schemes::V358.forms()[2].bit_count, 8);
    }
}
