//! Serializing/deserializing of encoding schemes.
//!
//! Encoding schemes are the way that the engine explains to other nodes how it parses labels.
//! Encoding schemes are represented as lists of **encoding forms**, an encoding form is a a packed
//! array of bits comprising of a pair of 5 bit numbers followed by a number of bits which is defined
//! by one of the numbers. Forms are packed together tightly in order to save bandwidth when
//! transferring encoding schemes across the wire.
//!
//! Serialization/deserialization example:
//!
//! ```rust
//! # use cjdns_core::{EncodingSchemeForm, EncodingScheme};
//! # use cjdns_core::{serialize_scheme, deserialize_scheme};
//!
//! // [{ bitCount: 4, prefix: "01", prefixLen: 1 }, { bitCount: 8, prefix: "00", prefixLen: 1 }]
//! // hex: 81 0c 08
//! // (reverse order of bytes)
//! // 08        0c        81
//! // 0000 1000 0000 1100 1000 0001
//! // read bits from right to left:
//! // 5 bits = prefix_len, next 5 bits = bit_count, next "prefix_len" bits = prefix
//! # let forms_to_scheme = |forms| EncodingScheme::try_new(forms).expect("invalid scheme");
//! let mut forms = [
//!     // params are: bit_count, prefix_len, prefix
//!     EncodingSchemeForm::try_new(4, 1, 1).expect("invalid scheme form"),
//!     EncodingSchemeForm::try_new(8, 1, 0).expect("invalid scheme form"),
//! ];
//!
//! let mut serialized = serialize_scheme(&forms_to_scheme(forms.as_ref())).unwrap();
//! assert_eq!(serialized, [0x81, 0x0c, 0x08].to_vec());
//! let mut deserialized = deserialize_scheme(&serialized).unwrap();
//! assert_eq!(deserialized, forms_to_scheme(forms.as_ref()));
//! ```

pub use encoding_scheme::*;
pub use encoding_serialization::{deserialize_scheme, serialize_scheme};
pub use errors::{EncodingSerializationError, SchemeValidationError};

mod encoding_serialization {
    //! Serialization and deserialization logic

    use super::EncodingSerializationError;
    use crate::{EncodingScheme, EncodingSchemeForm};

    /// Store encoding scheme into a byte vector array (bits sequence).
    ///
    /// Accepts `EncodingScheme`, encodes it as bits sequence
    /// and returns the result as bytes vector.
    pub fn serialize_scheme(scheme: &EncodingScheme) -> Result<Vec<u8>, EncodingSerializationError> {
        let mut result_vec: Vec<u8> = [].to_vec();
        let mut pos = 0_u32;
        let mut cur_byte_num = 0;
        let mut cur_bit_num = 0_u8;

        for form in scheme.iter() {
            let (bit_count, prefix_len, prefix) = form.params();
            // any form can be packed in u64
            let mut acc = 0_u64;

            if prefix_len > 31 {
                return Err(EncodingSerializationError::BadEncodingForm);
            }

            if bit_count < 1 || bit_count > 31 {
                return Err(EncodingSerializationError::BadEncodingForm);
            }

            if prefix_len > 0 {
                acc = acc | prefix as u64;
            }

            acc = acc << 5;
            acc = acc | bit_count as u64;

            acc = acc << 5;
            acc = acc | prefix_len as u64;

            let bits_needed = 5 + 5 + prefix_len;

            for _ in 0..bits_needed {
                if pos % 8 == 0 {
                    // start to work with new byte on each 8-th bit (alloc new byte in result_vec)
                    result_vec.push(0);
                    cur_byte_num = cur_byte_num + 1;
                    cur_bit_num = 0;
                }
                let mask = 1 << cur_bit_num;
                if (acc % 2) == 1 {
                    result_vec[cur_byte_num - 1] = result_vec[cur_byte_num - 1] | mask;
                }
                acc = acc >> 1;
                cur_bit_num = cur_bit_num + 1;
                pos = pos + 1;
            }

            assert_eq!(acc, 0);
        }

        Ok(result_vec)
    }

    /// Parse byte vector array (bits sequence) and transform it to encoding scheme.
    ///
    /// Parses bytes array into `EncodingScheme`.
    pub fn deserialize_scheme(scheme_bytes: &[u8]) -> Result<EncodingScheme, EncodingSerializationError> {
        if scheme_bytes.len() < 2 {
            return Err(EncodingSerializationError::BadSerializedData);
        }

        let mut result = Vec::new();
        let mut cur_pos = (scheme_bytes.len() * 8) as u32;

        loop {
            cur_pos = cur_pos - 5;
            let prefix_len = read_bits(scheme_bytes, cur_pos, 5);

            cur_pos = cur_pos - 5;
            let bit_count = read_bits(scheme_bytes, cur_pos, 5);

            cur_pos = cur_pos - prefix_len;

            // if prefix_len == 0 we simply read 0 bits from current position, receiving prefix = 0
            let prefix = read_bits(scheme_bytes, cur_pos, prefix_len as u8);

            result.push(EncodingSchemeForm::try_new(bit_count as u8, prefix_len as u8, prefix).expect("invalid encoding scheme form"));
            if cur_pos < (5 + 5) {
                // minimum size of scheme from (prefix_len == 0)
                break;
            }
        }
        let ret_scheme = EncodingScheme::try_new(&result).map_err(|_| EncodingSerializationError::BadSerializedData)?;
        Ok(ret_scheme)
    }

    fn read_bits(data: &[u8], position: u32, bits_amount: u8) -> u32 {
        assert!(bits_amount <= 32); // It is a programming error to request more than 32 bits
        assert!(position + bits_amount as u32 <= (data.len() as u32) * 8); // Programming error to read bits beyond input buffer

        let mut acc = 0; // maximum that can be parsed is prefix itself (max - 32 bits)
        if bits_amount == 0 {
            return acc; // reading 0 bits from any correct position returns 0x000000
        }
        let mut pos = position;
        let mut cur_byte_num;
        let mut cur_bit_num;
        let mut bits_left = bits_amount;

        while bits_left > 0 {
            cur_byte_num = (pos - (pos % 8)) / 8;
            cur_bit_num = pos % 8;

            // 0000...1...0000, where "1" is on position corresponding to current bit
            let byte_mask = 128 >> cur_bit_num;
            acc = acc << 1;

            // taking current byte by `cur_byte_num` index from end of `data`
            let cur_byte = data[data.len() - 1 - cur_byte_num as usize];
            if (cur_byte & byte_mask) == 0 {
                // if bit is 0 -> AND with "111111...11110"
                acc = acc & (!1);
            } else {
                // if bit is 1 -> OR with "00000...000001"
                acc = acc | 1;
            }
            pos = pos + 1;
            bits_left = bits_left - 1;
        }
        acc
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{EncodingScheme, SchemeValidationError};

        fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
            EncodingScheme::try_new(forms).expect("invalid scheme")
        }

        fn encoding_form(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
            EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).expect("invalid form")
        }

        fn validate(forms: &[EncodingSchemeForm]) -> Result<(), SchemeValidationError> {
            EncodingScheme::validate(forms)
        }

        #[test]
        fn test_is_sane_forms() {
            let mut input = [encoding_form(4, 1, 1), encoding_form(8, 1, 0)].to_vec();

            assert!(validate(&input).is_ok());

            // test non-empty prefix in single form
            input = [encoding_form(4, 1, 1)].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::SingleFormWithPrefix));

            // test non valid prefix_len
            input = [encoding_form(4, 0, 0), encoding_form(4, 4, 2)].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::MultiFormBadPrefix));

            // test bit_count not in ascending order
            input = [
                encoding_form(3, 3, 1),
                encoding_form(4, 4, 2),
                encoding_form(5, 5, 3),
                encoding_form(4, 6, 4),
                encoding_form(8, 7, 5),
            ]
            .to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::BitCountNotSorted));

            // test too big form size (bit_count + prefix_len > 59)
            input = [encoding_form(3, 3, 1), encoding_form(31, 29, 5)].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::TooBigForm));

            // test non-unique prefix in multiple forms
            input = [encoding_form(3, 3, 1), encoding_form(4, 4, 2), encoding_form(5, 5, 6), encoding_form(8, 9, 2)].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::DuplicatePrefix));
        }

        #[test]
        fn test_single_forms() {
            // obj: [ { bitCount: 4, prefix: "", prefixLen: 0 } ],
            // hex: '8000'
            // 80        00
            // 1000 0000 0000 0000
            let mut input = encoding_scheme([encoding_form(4, 0, 0)].as_ref());

            let mut serialized = serialize_scheme(&input).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L8
            assert_eq!(serialized, [0x80, 0x0].to_vec());
            let mut deserialized = deserialize_scheme(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());

            // obj: [ { bitCount: 8, prefix: "", prefixLen: 0 } ],
            // hex: '0001'
            // 00        01
            // 0000 0000 0000 0001
            input = encoding_scheme([encoding_form(8, 0, 0)].as_ref());

            serialized = serialize_scheme(&input).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L13
            assert_eq!(serialized, [0x0, 0x1].to_vec());
            deserialized = deserialize_scheme(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());
        }

        #[test]
        fn test_multiple_forms() {
            // { bitCount: 4, prefix: "01", prefixLen: 1 },
            // { bitCount: 8, prefix: "00", prefixLen: 1 },
            // 81        0c        08
            // 1000 0001 0000 1100 0000 1000
            let mut input = encoding_scheme([encoding_form(4, 1, 1), encoding_form(8, 1, 0)].as_ref());

            let mut serialized = serialize_scheme(&input).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L21
            assert_eq!(serialized, [0x81, 0x0c, 0x08].to_vec());
            let mut deserialized = deserialize_scheme(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());

            // name: "SCHEME_v358",
            // obj: [
            //   { bitCount: 3, prefix: "01", prefixLen: 1 },
            //   { bitCount: 5, prefix: "02", prefixLen: 2 },
            //   { bitCount: 8, prefix: "00", prefixLen: 2 }
            // ],
            // hex: '6114458100'
            // 61        14        45        81  :      00
            // 0110 0001 0001 0100 0100 0101 1000 0001 0000 0000
            input = encoding_scheme([encoding_form(3, 1, 1), encoding_form(5, 2, 2), encoding_form(8, 2, 0)].as_ref());

            serialized = serialize_scheme(&input).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L30
            assert_eq!(serialized, [0x61, 0x14, 0x45, 0x81, 0x0].to_vec());
            deserialized = deserialize_scheme(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());
        }

        #[test]
        fn test_forms_pack_with_sequential_parameters() {
            // test of forms pack with different parameters
            let mut pack: Vec<EncodingSchemeForm> = [].to_vec();
            let mut prefix = 1_u32;

            for i in 1..30 {
                let prefix_len = i;
                let bit_count = i;
                pack.push(encoding_form(bit_count, prefix_len, prefix));
                prefix = prefix << 1;
            }

            assert!(validate(&pack).is_ok());
            let scheme = EncodingScheme::try_new(&pack).expect("invalid scheme");
            let serialized = serialize_scheme(&scheme).expect("failed to serialize");
            let deserialized = deserialize_scheme(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, scheme);
        }
    }
}

mod encoding_scheme {
    //! Routing label encoding scheme.

    use std::collections::HashSet;
    use std::ops::Deref;
    use serde::Serialize;

    use crate::encoding::errors::{FormValidationError, SchemeValidationError};

    /// In the old days every label needed to be topped with 0001.
    /// To make sure that no label would ever go over 64 bits even with 0001 spliced on the top of it, we use this reservation.
    ///
    /// Now that we have a shift field in the header, that's all but obsolete, a label can go up to bit 64 if needed, as long as the final bit is a 1.
    const FORM_MAX_BIT_SIZE: u8 = 59;

    /// Encoding scheme - an iterable list of scheme forms.
    ///
    /// Schemes are comparable for equality, immutable, opaque and iterable.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct EncodingScheme(Vec<EncodingSchemeForm>);

    /// A form of an encoding scheme. Form is used as follows to encode a director:
    ///
    /// ```text
    /// [     director     ] [     form.prefix     ]
    /// ^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^
    /// form.bit_count bits   form.prefix_len bits
    /// ```
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
    pub struct EncodingSchemeForm {
        bit_count: u8, // bit_count going first is important for EncodingScheme ordering
        prefix_len: u8,
        prefix: u32,
    }

    impl EncodingSchemeForm {
        /// Instantiates `EncodingSchemeForm`.
        ///
        /// Returns an error in several situations:
        /// * encoding `bit_count` value is out of valid range, which is 1..32
        /// * `prefix_len` is too small for the provided `prefix`
        pub fn try_new(bit_count: u8, prefix_len: u8, prefix: u32) -> Result<Self, FormValidationError> {
            if bit_count == 0 || bit_count > 31 {
                return Err(FormValidationError::BadBitCount);
            }
            let prefix_max_value = (1 << prefix_len) - 1;
            if prefix > prefix_max_value {
                return Err(FormValidationError::InvalidPrefixData);
            }
            Ok(EncodingSchemeForm { bit_count, prefix_len, prefix })
        }

        /// Returns encoding scheme form params in respected order:
        /// * bit count;
        /// * prefix length;
        /// * prefix itself.
        pub fn params(&self) -> (u8, u8, u32) {
            (self.bit_count, self.prefix_len, self.prefix)
        }

        /// As a scheme is represented as an array of **forms**, this function will tell you how many bits of
        /// label space is occupied by a representation of a given form.
        pub fn size_bits(&self) -> u8 {
            self.bit_count + self.prefix_len
        }
    }

    impl EncodingScheme {
        /// Instantiates `EncodingScheme`.
        ///
        /// Returns an error if forms validation failed. See `validate` function docs for more info.
        pub fn try_new(forms: &[EncodingSchemeForm]) -> Result<Self, SchemeValidationError> {
            let _ = Self::validate(forms)?;
            Ok(Self(forms.to_vec()))
        }

        /// Validates encoding scheme.
        ///
        /// Returns an error in several situations:
        /// * provided forms slice length is 0 or greater than 31
        /// * `bit_count` value of any form is out of valid range - 1..32
        /// * `prefix_len` value of any form is out if valid range - 1..32 (for multiple forms scheme)
        /// * forms are not in ascending order by `bits_count` key
        /// * bits size of a form is greater than 59 (for multiple forms scheme)
        /// * forms with equal prefixes are in scheme
        ///
        /// Each returned value fully reflects error type.
        pub fn validate(forms: &[EncodingSchemeForm]) -> Result<(), SchemeValidationError> {
            // each form must have a different prefix_len and bit_count;
            // can only be expressed in 5 bits limiting it to 31 bits max and a form
            // using zero bits is not allowed so there are only 31 max possibilities.
            if forms.len() == 0 || forms.len() > 31 {
                return Err(SchemeValidationError::InvalidFormsAmount);
            }

            if forms.len() == 1 {
                // if single form - prefix must be empty
                let form = forms[0];
                let (_, prefix_len, prefix) = form.params();
                if prefix_len != 0 || prefix != 0 {
                    return Err(SchemeValidationError::SingleFormWithPrefix);
                }
                return Ok(());
            }

            let mut last_bit_count = 0;
            let mut used_prefixes = HashSet::new();

            for form in forms {
                let (bit_count, prefix_len, prefix) = form.params();
                // when multiple forms - prefixes must be non-empty
                if prefix_len == 0 || prefix_len > 31 {
                    return Err(SchemeValidationError::MultiFormBadPrefix);
                }

                // forms must have bit_count in ascending order
                if last_bit_count > bit_count {
                    return Err(SchemeValidationError::BitCountNotSorted);
                }
                last_bit_count = bit_count;

                if form.size_bits() > FORM_MAX_BIT_SIZE {
                    return Err(SchemeValidationError::TooBigForm);
                }

                // forms must be distinguishable by their prefix
                if used_prefixes.contains(&prefix) {
                    return Err(SchemeValidationError::DuplicatePrefix);
                }
                used_prefixes.insert(prefix);
            }
            Ok(())
        }
    }

    impl Deref for EncodingScheme {
        type Target = [EncodingSchemeForm];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub mod schemes {
        //! Well-known encoding schemes

        use super::{EncodingScheme, EncodingSchemeForm};

        lazy_static! {
            /// Fixed-length 4 bit scheme.
            pub static ref F4: EncodingScheme = encoding_scheme(&[EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 0,
                prefix: 0,
            }]);

            /// Fixed-length 8 bit scheme.
            pub static ref F8: EncodingScheme = encoding_scheme(&[EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 0,
                prefix: 0,
            }]);

            /// Variable-length 4 or 8 bit scheme.
            pub static ref V48: EncodingScheme = encoding_scheme(&[
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
            pub static ref V358: EncodingScheme = encoding_scheme(&[
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
            pub static ref V37: EncodingScheme = encoding_scheme(&[
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

        /// Returns an iterator over all the well-known encoding schemes
        pub fn all() -> impl Iterator<Item = &'static EncodingScheme> + 'static {
            lazy_static! {
                static ref ALL: [EncodingScheme; 5] = [F4.clone(), F8.clone(), V48.clone(), V358.clone(), V37.clone()];
            }
            ALL.iter()
        }

        fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
            EncodingScheme::try_new(forms).expect("invalid form")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{schemes, EncodingScheme, EncodingSchemeForm};

        fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
            EncodingScheme::try_new(forms).expect("invalid scheme")
        }

        fn encoding_form(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
            EncodingSchemeForm { bit_count, prefix_len, prefix }
        }

        #[test]
        fn encoding_scheme_iteration() {
            assert_eq!(
                encoding_scheme(&[encoding_form(4, 2, 0b00), encoding_form(4, 2, 0b01)])
                    .into_iter()
                    .cloned()
                    .collect::<Vec<EncodingSchemeForm>>(),
                vec![encoding_form(4, 2, 0b00), encoding_form(4, 2, 0b01)]
            );
        }

        #[test]
        fn schemes() {
            assert_eq!(&**schemes::F8, &[encoding_form(8, 0, 0)]);

            // smallest to biggest
            assert_eq!(schemes::V358[0].bit_count, 3);
            assert_eq!(schemes::V358[2].bit_count, 8);
        }
    }
}

mod errors {
    use thiserror::Error;

    /// Error returned when scheme validation fails
    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum SchemeValidationError {
        /// Invalid scheme forms length. Should be in 1..32 range.
        #[error("Invalid encoding scheme: amount of encoding forms is not in range of (1..32)")]
        InvalidFormsAmount,

        /// Scheme with single form must not have non-empty prefix value
        #[error("Invalid encoding scheme: single form has non-empty prefix")]
        SingleFormWithPrefix,

        /// Scheme with multiple forms must have non-empty prefix value
        #[error("Invalid encoding scheme: multiple forms - prefix length is out of bounds (1..32)")]
        MultiFormBadPrefix,

        /// Multiple forms should have `bit_count` in ascending order
        #[error("Invalid encoding scheme: multiple forms should have bit_count in ascending order")]
        BitCountNotSorted,

        /// Multiple forms must have unique prefixes
        #[error("Invalid encoding scheme: multiple forms must have unique prefixes")]
        DuplicatePrefix,

        /// Encoding scheme cannot be represented in the usable space in a 64-bit label
        #[error("Invalid encoding scheme: encoding scheme cannot be represented in the usable space in a 64-bit label")]
        TooBigForm,
    }

    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum FormValidationError {
        /// Scheme bit count value out of valid range (which is 1..32)
        #[error("Invalid encoding form: `bit_count` out of bounds (1..32)")]
        BadBitCount,

        /// Encoded prefix length is insufficient for the provided prefix
        #[error("Invalid encoding form: `prefix_len` is to little for provided `prefix`")]
        InvalidPrefixData,
    }

    /// Error returned when encoding scheme for serialization/deserialization fails
    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum EncodingSerializationError {
        /// Returned when scheme serialization fails
        #[error("Invalid serialized encoding scheme")]
        BadSerializedData,

        /// Returned when encoding form deserialization fails
        #[error("Invalid encoding form")]
        BadEncodingForm,
    }
}
