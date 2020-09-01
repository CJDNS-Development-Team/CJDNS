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
//!     EncodingSchemeForm { bit_count: 4, prefix_len: 1, prefix: 1 },
//!     EncodingSchemeForm { bit_count: 8, prefix_len: 1, prefix: 0 },
//! ].to_vec();
//!
//! let mut serialized = serialize_forms(&input.to_vec()).unwrap();
//! assert_eq!(serialized, [0x81, 0x0c, 0x08].to_vec());
//! let mut deserialized = deserialize_forms(&serialized).unwrap();
//! assert_eq!(deserialized, input);
//! ```

use std::collections::HashSet;

use thiserror::Error;

use crate::EncodingSchemeForm;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EncodingSchemeError {
    #[error("Vector passed to method is emtpy")]
    ArgumentVectorIsEmpty,
    #[error("Vector passed to method has too big size")]
    ArgumentVectorSizeTooBig,
    #[error("Vector passed to method is too small")]
    ArgumentVectorTooSmall,
    #[error("Numerical argument is out of bounds")]
    ArgumentOutOfBounds,
    #[error("Single form in scheme has non-empty prefix")]
    SchemeNotValidNonEmptyPrefixSingleForm,
    #[error("Form has bit_count out of bounds (from 1 to 31)")]
    SchemeNotValidBitCountOutOfBounds,
    #[error("Multiple forms - prefix is out of bounds (must be from 1 to 31)")]
    SchemeNotValidPrefixLenOutOfBounds,
    #[error("Multiple forms - bit_count must be in ascending order")]
    SchemeNotValidBitCountNotInAscendingOrder,
    #[error("Form size too big (bit_count + prefix_len > 59)")]
    SchemeNotValidFormSizeTooBig,
    #[error("Multiple forms - must have unique prefixes - found non-unique")]
    SchemeNotValidPrefixNonUnique,
}

type Result<T> = std::result::Result<T, EncodingSchemeError>;

/// As a scheme is represented as an array of **forms**, this function will tell you how many bits of
/// label space is occupied by a representation of a given form.
pub fn form_size(form: &EncodingSchemeForm) -> u8 {
    return form.bit_count + form.prefix_len;
}

/// Validates encoding scheme. Returned value in case of error describes the problem.
pub fn validate(forms: &[EncodingSchemeForm]) -> Result<()> {
    if forms.len() == 0 {
        return Err(EncodingSchemeError::ArgumentVectorIsEmpty);
    }

    if forms.len() > 31 {
        // each form must have a different prefix_len and bit_count;
        // can only be expressed in 5 bits limiting it to 31 bits max and a form
        // using zero bits is not allowed so there are only 31 max possibilities.
        return Err(EncodingSchemeError::ArgumentVectorSizeTooBig);
    }

    if forms.len() == 1 {
        // if single form - prefix must be empty
        let form = forms[0];
        if form.prefix_len != 0 || form.prefix != 0 {
            return Err(EncodingSchemeError::SchemeNotValidNonEmptyPrefixSingleForm);
        }
        if form.bit_count == 0 || form.bit_count > 31 {
            return Err(EncodingSchemeError::SchemeNotValidBitCountOutOfBounds);
        }
        return Ok(());
    }

    let mut last_bit_count = 0;
    let mut used_prefixes = HashSet::new();

    for form in forms {
        // when multiple forms - prefixes must be non-empty
        if form.prefix_len == 0 || form.prefix_len > 31 {
            return Err(EncodingSchemeError::SchemeNotValidPrefixLenOutOfBounds);
        }

        if form.bit_count == 0 || form.bit_count > 31 {
            return Err(EncodingSchemeError::SchemeNotValidBitCountOutOfBounds);
        }

        // forms must have bit_count in ascending order
        if last_bit_count > form.bit_count {
            return Err(EncodingSchemeError::SchemeNotValidBitCountNotInAscendingOrder);
        }
        last_bit_count = form.bit_count;

        // bit_count + prefix_len must be < 59 bits
        if form_size(form) > 59 {
            return Err(EncodingSchemeError::SchemeNotValidFormSizeTooBig);
        }

        // forms must be distinguishable by their prefix
        if used_prefixes.contains(&form.prefix) {
            return Err(EncodingSchemeError::SchemeNotValidPrefixNonUnique);
        }
        used_prefixes.insert(form.prefix);
    }
    Ok(())
}

/// Store encoding scheme (array of `EncodingSchemeForm`) into a byte vector array (bits sequence).
///
/// Accepts vector of `EncodingSchemeForm`s, encodes them as bits sequence
/// and returns the result as bytes vector.
pub fn serialize_forms(encforms: &[EncodingSchemeForm]) -> Result<Vec<u8>> {
    let mut result_vec: Vec<u8> = [].to_vec();
    let mut pos = 0u32;
    let mut cur_byte_num = 0;
    let mut cur_bit_num = 0u8;

    for encform in encforms {
        // any form can be packed in u64
        let mut accum64 = 0u64;

        // [TODO] fix err handling
        if encform.prefix_len > 31 {
            return Err(EncodingSchemeError::ArgumentOutOfBounds);
        }

        if encform.bit_count < 1 || encform.bit_count > 31 {
            return Err(EncodingSchemeError::ArgumentOutOfBounds);
        }

        if encform.prefix_len > 0 {
            accum64 = accum64 | u64::from(encform.prefix);
        }

        accum64 = accum64 << 5;
        accum64 = accum64 | u64::from(encform.bit_count);

        accum64 = accum64 << 5;
        accum64 = accum64 | u64::from(encform.prefix_len);

        let bits_needed = 5 + 5 + encform.prefix_len;
        // println!("[DEBUG] accum: {:064b}", accum64);

        for _ in 0..bits_needed {
            if pos % 8 == 0 {
                // start to work with new byte on each 8-th bit (alloc new byte in result_vec)
                result_vec.push(0u8);
                cur_byte_num = cur_byte_num + 1;
                cur_bit_num = 0;
            }
            let mask = 1u8 << cur_bit_num;
            if (accum64 % 2) == 1 {
                result_vec[cur_byte_num - 1] = result_vec[cur_byte_num - 1] | mask;
            }
            accum64 = accum64 >> 1;
            cur_bit_num = cur_bit_num + 1;
            pos = pos + 1;
        }

        assert_eq!(accum64, 0u64);
    }

    Ok(result_vec)
}

fn read_n_bits_from_position_into_u32(data: &[u8], position: u32, bits_amount: u8) -> Result<u32> {
    // TODO check errors handling
    if bits_amount > 32 {
        return Err(EncodingSchemeError::ArgumentOutOfBounds);
    }

    if (position + (bits_amount as u32)) > ((data.len() as u32) * 8) {
        return Err(EncodingSchemeError::ArgumentOutOfBounds);
    }
    let mut accum = 0u32; // maximum that can be parsed is prefix itself (max - 32 bits)
    if bits_amount == 0 {
        // [NOTE] reading 0 bits from any correct position returns 0x000000
        return Ok(accum);
    }
    let mut pos = position;
    let mut cur_byte_num;
    let mut cur_bit_num;
    let mut bits_left = bits_amount;

    while bits_left > 0 {
        cur_byte_num = (pos - (pos % 8)) / 8;
        cur_bit_num = pos % 8;

        // 0000...1...0000, where "1" is on position correspondig to current bit
        let byte_mask = 128u8 >> cur_bit_num;
        accum = accum << 1;

        // taking current byte by `cur_byte_num` index from end of `data`
        let cur_byte = data[data.len() - 1 - cur_byte_num as usize];
        if (cur_byte & byte_mask) == 0 {
            // if bit is 0 -> AND with "111111...11110"
            accum = accum & (!1u32);
        } else {
            // if bit is 1 -> OR with "00000...000001"
            accum = accum | 1u32;
        }
        pos = pos + 1;
        bits_left = bits_left - 1;
    }
    Ok(accum)
}

/// Parse byte vector array (bits sequence) and transform it to encoding scheme.
///
/// Accepts bytes array, parses it and returns vector of `EncodingSchemeForm`s.
pub fn deserialize_forms(form_bytes: &[u8]) -> Result<Vec<EncodingSchemeForm>> {
    // TODO handle errors
    if form_bytes.len() < 2 {
        return Err(EncodingSchemeError::ArgumentVectorTooSmall);
    }
    if form_bytes.len() == 0 {
        return Err(EncodingSchemeError::ArgumentVectorIsEmpty);
    }

    let mut result = Vec::new();
    let mut cur_pos = (form_bytes.len() * 8) as u32;

    loop {
        cur_pos = cur_pos - 5;
        let prefix_len = read_n_bits_from_position_into_u32(form_bytes, cur_pos, 5).unwrap(); //TODO need proper error handling, probably redesign

        cur_pos = cur_pos - 5;
        let bit_count = read_n_bits_from_position_into_u32(form_bytes, cur_pos, 5).unwrap(); //TODO need proper error handling, probably redesign

        cur_pos = cur_pos - prefix_len;

        // if prefix_len == 0 we simply read 0 bits from current position, receiving prefix = 0u32
        let prefix = read_n_bits_from_position_into_u32(form_bytes, cur_pos, prefix_len as u8).unwrap(); //TODO need proper error handling, probably redesign

        // println!("[DEBUG] prefix: {:b}, bit_count: {:05b}, prefix_len: {:05b}", prefix, bit_count, prefix_len);
        result.push(EncodingSchemeForm {
            prefix_len: prefix_len as u8,
            bit_count: bit_count as u8,
            prefix,
        });
        if cur_pos < (5 + 5) { // minimum size of scheme from (prefix_len == 0)
            break;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sane_forms() {
        let mut input = [
            EncodingSchemeForm { bit_count: 4, prefix_len: 1, prefix: 1 },
            EncodingSchemeForm { bit_count: 8, prefix_len: 1, prefix: 0 },
        ].to_vec();

        assert!(validate(&input).is_ok());

        // test non-empty prefix in single form
        input = [
            EncodingSchemeForm { bit_count: 4, prefix_len: 1, prefix: 1 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidNonEmptyPrefixSingleForm));

        // test non-valid bit_count single form
        input = [
            EncodingSchemeForm { bit_count: 34, prefix_len: 0, prefix: 0 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidBitCountOutOfBounds));

        // test non-valid bit_count multiple forms
        input = [
            EncodingSchemeForm { bit_count: 30, prefix_len: 1, prefix: 1 },
            EncodingSchemeForm { bit_count: 34, prefix_len: 2, prefix: 2 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidBitCountOutOfBounds));

        // test non valid prefix_len
        input = [
            EncodingSchemeForm { bit_count: 3, prefix_len: 32, prefix: 111 },
            EncodingSchemeForm { bit_count: 4, prefix_len: 4, prefix: 2 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidPrefixLenOutOfBounds));

        // test bit_count not in ascending order
        input = [
            EncodingSchemeForm { bit_count: 3, prefix_len: 3, prefix: 1 },
            EncodingSchemeForm { bit_count: 4, prefix_len: 4, prefix: 2 },
            EncodingSchemeForm { bit_count: 5, prefix_len: 5, prefix: 3 },
            EncodingSchemeForm { bit_count: 4, prefix_len: 6, prefix: 4 },
            EncodingSchemeForm { bit_count: 8, prefix_len: 7, prefix: 5 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidBitCountNotInAscendingOrder));

        // test too big form size (bit_count + prefix_len > 59)
        input = [
            EncodingSchemeForm { bit_count: 3, prefix_len: 3, prefix: 1 },
            EncodingSchemeForm { bit_count: 31, prefix_len: 29, prefix: 5 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidFormSizeTooBig));

        // test non-unique prefix in multiple forms
        input = [
            EncodingSchemeForm { bit_count: 3, prefix_len: 3, prefix: 1 },
            EncodingSchemeForm { bit_count: 4, prefix_len: 4, prefix: 2 },
            EncodingSchemeForm { bit_count: 5, prefix_len: 5, prefix: 6 },
            EncodingSchemeForm { bit_count: 8, prefix_len: 9, prefix: 2 },
        ].to_vec();
        assert_eq!(validate(&input), Err(EncodingSchemeError::SchemeNotValidPrefixNonUnique));
    }

    #[test]
    fn test_single_forms() {
        // obj: [ { bitCount: 4, prefix: "", prefixLen: 0 } ],
        // hex: '8000'
        // 80        00
        // 1000 0000 0000 0000
        let mut input = [
            EncodingSchemeForm { bit_count: 4, prefix_len: 0, prefix: 0 }
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
            EncodingSchemeForm { bit_count: 8, prefix_len: 0, prefix: 0 }
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
            EncodingSchemeForm { bit_count: 4, prefix_len: 1, prefix: 1 },
            EncodingSchemeForm { bit_count: 8, prefix_len: 1, prefix: 0 },
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
            EncodingSchemeForm { bit_count: 3, prefix_len: 1, prefix: 1 },
            EncodingSchemeForm { bit_count: 5, prefix_len: 2, prefix: 2 },
            EncodingSchemeForm { bit_count: 8, prefix_len: 2, prefix: 0 },
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
        let mut prefix = 1u32;

        for i in 1..30 {
            let prefix_len = i;
            let bit_count = i;
            pack.push(EncodingSchemeForm {
                bit_count,
                prefix_len,
                prefix: prefix as u32,
            });
            prefix = prefix << 1;
        }

        // println!("[DEBUG] Forms pack: {:?}", pack);
        assert!(validate(&pack).is_ok());
        let serialized = serialize_forms(&pack).expect("failed to serialize");
        let deserialized = deserialize_forms(&serialized).expect("failed to deserialize");
        assert_eq!(deserialized, pack);
    }
}