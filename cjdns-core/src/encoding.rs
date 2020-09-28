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
//! # use cjdns_core::EncodingSchemeForm;
//! # use cjdns_core::{serialize_forms, deserialize_forms};
//!
//! // [{ bitCount: 4, prefix: "01", prefixLen: 1 }, { bitCount: 8, prefix: "00", prefixLen: 1 }]
//! // hex: 81 0c 08
//! // (reverse order of bytes)
//! // 08        0c        81
//! // 0000 1000 0000 1100 1000 0001
//! // read bits from right to left:
//! // 5 bits = prefix_len, next 5 bits = bit_count, next "prefix_len" bits = prefix
//!
//! let mut input = [
//!     // params are: bit_count, prefix_len, prefix
//!     EncodingSchemeForm::try_new(4, 1, 1).expect("invalid scheme form"),
//!     EncodingSchemeForm::try_new(8, 1, 0).expect("invalid scheme form"),
//! ].to_vec();
//!
//! let mut serialized = serialize_forms(&input.to_vec()).unwrap();
//! assert_eq!(serialized, [0x81, 0x0c, 0x08].to_vec());
//! let mut deserialized = deserialize_forms(&serialized).unwrap();
//! assert_eq!(deserialized, input);
//! ```

pub use encoding_serde::{deserialize_forms, serialize_forms};
pub use encoding_scheme::*;

mod encoding_serde {
    use super::errors::EncodingSerDeError;
    use crate::EncodingSchemeForm;

    /// Store encoding scheme (array of `EncodingSchemeForm`) into a byte vector array (bits sequence).
    ///
    /// Accepts vector of `EncodingSchemeForm`s, encodes them as bits sequence
    /// and returns the result as bytes vector.
    pub fn serialize_forms(forms: &[EncodingSchemeForm]) -> Result<Vec<u8>, EncodingSerDeError> {
        let mut result_vec: Vec<u8> = [].to_vec();
        let mut pos = 0_u32;
        let mut cur_byte_num = 0;
        let mut cur_bit_num = 0_u8;

        for form in forms {
            let (bit_count, prefix_len, prefix) = form.params();
            // any form can be packed in u64
            let mut acc = 0_u64;

            if prefix_len > 31 {
                return Err(EncodingSerDeError::BadEncodingForm);
            }

            if bit_count < 1 || bit_count > 31 {
                return Err(EncodingSerDeError::BadEncodingForm);
            }

            if prefix_len > 0 {
                acc = acc | prefix as u64;
            }

            acc = acc << 5;
            acc = acc | bit_count as u64;

            acc = acc << 5;
            acc = acc | prefix_len as u64;

            let bits_needed = 5 + 5 + prefix_len;
            // println!("[DEBUG] accum: {:064b}", accum64);

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

    /// Parse byte vector array (bits sequence) and transform it to encoding scheme.
    ///
    /// Accepts bytes array, parses it and returns vector of `EncodingSchemeForm`s.
    pub fn deserialize_forms(form_bytes: &[u8]) -> Result<Vec<EncodingSchemeForm>, EncodingSerDeError> {
        if form_bytes.len() < 2 {
            return Err(EncodingSerDeError::BadSerializedData);
        }

        let mut result = Vec::new();
        let mut cur_pos = (form_bytes.len() * 8) as u32;

        loop {
            cur_pos = cur_pos - 5;
            let prefix_len = read_bits(form_bytes, cur_pos, 5);

            cur_pos = cur_pos - 5;
            let bit_count = read_bits(form_bytes, cur_pos, 5);

            cur_pos = cur_pos - prefix_len;

            // if prefix_len == 0 we simply read 0 bits from current position, receiving prefix = 0
            let prefix = read_bits(form_bytes, cur_pos, prefix_len as u8);

            // println!("[DEBUG] prefix: {:b}, bit_count: {:05b}, prefix_len: {:05b}", prefix, bit_count, prefix_len);
            result.push(
                EncodingSchemeForm::try_new(
                    bit_count as u8,
                    prefix_len as u8,
                    prefix
                )
                .expect("TODO msg") // todo
            );
            if cur_pos < (5 + 5) { // minimum size of scheme from (prefix_len == 0)
                break;
            }
        }

        Ok(result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{EncodingScheme, encoding::errors::SchemeValidationError};

        fn encoding_form(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
            EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).expect("invalid form")
        }

        fn validate(forms: &[EncodingSchemeForm]) -> Result<(), SchemeValidationError> {
            EncodingScheme::validate(forms)
        }

        #[test]
        fn test_is_sane_forms() {
            let mut input = [
                encoding_form(4, 1, 1),
                encoding_form(8, 1, 0),
            ].to_vec();

            assert!(validate(&input).is_ok());

            // test non-empty prefix in single form
            input = [
                encoding_form(4, 1, 1),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::SingleFormWithPrefix));

            // test non-valid bit_count single form
            input = [
                encoding_form(34, 0, 0),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::BadBitCount));

            // test non-valid bit_count multiple forms
            input = [
                encoding_form(30, 1, 1),
                encoding_form(34, 2, 2),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::BadBitCount));

            // test non valid prefix_len
            input = [
                encoding_form(3, 32, 111),
                encoding_form(4, 4, 2),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::MultiFormBadPrefix));

            // test bit_count not in ascending order
            input = [
                encoding_form(3, 3, 1),
                encoding_form(4, 4, 2),
                encoding_form(5, 5, 3),
                encoding_form(4, 6, 4),
                encoding_form(8, 7, 5),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::BitCountNotSorted));

            // test too big form size (bit_count + prefix_len > 59)
            input = [
                encoding_form(3, 3, 1),
                encoding_form(31, 29, 5),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::TooBigForm));

            // test non-unique prefix in multiple forms
            input = [
                encoding_form(3, 3, 1),
                encoding_form(4, 4, 2),
                encoding_form(5, 5, 6),
                encoding_form(8, 9, 2),
            ].to_vec();
            assert_eq!(validate(&input), Err(SchemeValidationError::DuplicatePrefix));
        }

        #[test]
        fn test_single_forms() {
            // obj: [ { bitCount: 4, prefix: "", prefixLen: 0 } ],
            // hex: '8000'
            // 80        00
            // 1000 0000 0000 0000
            let mut input = [
                encoding_form(4, 0, 0),
            ].to_vec();

            let mut serialized = serialize_forms(&input.to_vec()).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L8
            assert_eq!(serialized, [0x80, 0x0].to_vec());
            let mut deserialized = deserialize_forms(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());

            // obj: [ { bitCount: 8, prefix: "", prefixLen: 0 } ],
            // hex: '0001'
            // 00        01
            // 0000 0000 0000 0001
            input = [
                encoding_form(8, 0, 0),
            ].to_vec();

            serialized = serialize_forms(&input.to_vec()).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L13
            assert_eq!(serialized, [0x0, 0x1].to_vec());
            deserialized = deserialize_forms(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());
        }

        #[test]
        fn test_multiple_forms() {
            // { bitCount: 4, prefix: "01", prefixLen: 1 },
            // { bitCount: 8, prefix: "00", prefixLen: 1 },
            // 81        0c        08
            // 1000 0001 0000 1100 0000 1000
            let mut input = [
                encoding_form(4, 1, 1),
                encoding_form(8, 1, 0),
            ].to_vec();

            let mut serialized = serialize_forms(&input.to_vec()).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L21
            assert_eq!(serialized, [0x81, 0x0c, 0x08].to_vec());
            let mut deserialized = deserialize_forms(&serialized).expect("failed to deserialize");
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
            input = [
                encoding_form(3, 1, 1),
                encoding_form(5, 2, 2),
                encoding_form(8, 2, 0),
            ].to_vec();

            serialized = serialize_forms(&input.to_vec()).expect("failed to serialize");
            // https://github.com/cjdelisle/cjdnsencode/blob/89216230daa82eb43689c6af48de3c6a138002f1/test.js#L30
            assert_eq!(serialized, [0x61, 0x14, 0x45, 0x81, 0x0].to_vec());
            deserialized = deserialize_forms(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, input);
            assert!(validate(&deserialized).is_ok());
        }

        #[test]
        fn test_forms_pack_with_sequental_parameters() {
            // test of forms pack with different parameters
            let mut pack: Vec<EncodingSchemeForm> = [].to_vec();
            let mut prefix = 1_u32;

            for i in 1..30 {
                let prefix_len = i;
                let bit_count = i;
                pack.push(encoding_form(bit_count, prefix_len, prefix));
                prefix = prefix << 1;
            }

            // println!("[DEBUG] Forms pack: {:?}", pack);
            assert!(validate(&pack).is_ok());
            let serialized = serialize_forms(&pack).expect("failed to serialize");
            let deserialized = deserialize_forms(&serialized).expect("failed to deserialize");
            assert_eq!(deserialized, pack);
        }
    }
}

mod encoding_scheme {
    //! Routing label encoding scheme.

    use std::slice;
    use std::collections::HashSet;

    use crate::encoding::errors::SchemeValidationError;

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
        bit_count: u8, // bit_count going first is important for EncodingScheme ordering
        prefix_len: u8,
        prefix: u32,
    }

    pub mod schemes {
        use super::{EncodingSchemeForm, EncodingScheme};

        fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
            EncodingScheme::try_new(forms).expect("invalid form")
        }

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

        pub fn all() -> impl Iterator<Item=&'static EncodingScheme> + 'static {
            lazy_static! {
                static ref ALL: [EncodingScheme; 5] = [F4.clone(), F8.clone(), V48.clone(), V358.clone(), V37.clone()];
            }
            ALL.iter()
        }
    }

    impl EncodingSchemeForm {
        // todo what should I validate here?!
        pub fn try_new(bit_count: u8, prefix_len: u8, prefix: u32) -> Result<Self, ()> {
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
        pub fn try_new(forms: &[EncodingSchemeForm]) -> Result<Self, SchemeValidationError> {
            let _ = Self::validate(forms)?;
            Ok(Self(forms.to_vec()))
        }

        pub fn forms(&self) -> &[EncodingSchemeForm] {
            &self.0
        }

        /// Validates encoding scheme. Returned value in case of error describes the problem.
        pub fn validate(forms: &[EncodingSchemeForm]) -> Result<(), SchemeValidationError> {
            if forms.len() == 0 {
                return Err(SchemeValidationError::NoEncodingForms);
            }

            if forms.len() > 31 {
                // each form must have a different prefix_len and bit_count;
                // can only be expressed in 5 bits limiting it to 31 bits max and a form
                // using zero bits is not allowed so there are only 31 max possibilities.
                return Err(SchemeValidationError::TooManyEncodingForms);
            }

            if forms.len() == 1 {
                // if single form - prefix must be empty
                let form = forms[0];
                let (bit_count, prefix_len, prefix) = form.params();
                if prefix_len != 0 || prefix != 0 {
                    return Err(SchemeValidationError::SingleFormWithPrefix);
                }
                if bit_count == 0 || bit_count > 31 {
                    return Err(SchemeValidationError::BadBitCount);
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

                if bit_count == 0 || bit_count > 31 {
                    return Err(SchemeValidationError::BadBitCount);
                }

                // forms must have bit_count in ascending order
                if last_bit_count > bit_count {
                    return Err(SchemeValidationError::BitCountNotSorted);
                }
                last_bit_count = bit_count;

                // bit_count + prefix_len must be < 59 bits
                if form.size_bits() > 59 {
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
        
        fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
            EncodingScheme::try_new(forms).expect("invalid scheme")
        }

        fn encoding_form(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
            EncodingSchemeForm {
                bit_count,
                prefix_len,
                prefix,
            }
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
            assert_eq!(schemes::F8.forms(), &[encoding_form(8, 0, 0)]);

            // smallest to biggest
            assert_eq!(schemes::V358.forms()[0].bit_count, 3);
            assert_eq!(schemes::V358.forms()[2].bit_count, 8);
        }
    }
}

mod errors {
    use thiserror::Error;

    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum SchemeValidationError {
        #[error("Invalid encoding scheme: no encoding forms defined")]
        NoEncodingForms,
        #[error("Invalid encoding scheme: too many encoding forms defined (max 31)")]
        TooManyEncodingForms,
        #[error("Invalid encoding scheme: single form has non-empty prefix")]
        SingleFormWithPrefix,
        #[error("Invalid encoding scheme: form has bit_count out of bounds (1..31)")]
        BadBitCount,
        #[error("Invalid encoding scheme: multiple forms - prefix length is out of bounds (1..31)")]
        MultiFormBadPrefix,
        #[error("Invalid encoding scheme: multiple forms should have bit_count in ascending order")]
        BitCountNotSorted,
        #[error("Invalid encoding scheme: multiple forms must have unique prefixes")]
        DuplicatePrefix,
        #[error("Invalid encoding scheme: form size too big (bit_count + prefix_len > 59)")]
        TooBigForm,
    }

    #[derive(Error, Debug, PartialEq, Eq)]
    pub enum EncodingSerDeError {
        #[error("Invalid serialized encoding scheme")]
        BadSerializedData,
        #[error("Invalid encoding form")]
        BadEncodingForm,
    }
}
