use std::iter::FromIterator;

pub const BASE32_ENCODED_STRING_LEN: usize = 52;

pub fn base32_encode(input: [u8; 32]) -> String {
    let alphabet = "0123456789bcdfghjklmnpqrstuvwxyz".chars().collect::<Vec<char>>();

    let (mut out_idx, mut in_idx) = (0usize, 0usize);
    let (mut shifts, mut work) = (0usize, 0usize);
    let mut output: Vec<char> = Vec::new();

    while in_idx < input.len() {
        work |= (input[in_idx] as usize) << shifts;
        shifts += 8;

        while shifts >= 5 {
            output.insert(out_idx, alphabet[work & 31]);
            shifts -= 5;
            work >>= 5;
            out_idx += 1;
        }

        in_idx += 1;
    }

    if shifts != 0 {
        output.insert(out_idx, alphabet[work & 31]);
    }

    String::from_iter(output)
}

pub fn base32_decode(input: &str) -> Result<Vec<u8>, &str> {
    if input.len() != BASE32_ENCODED_STRING_LEN {
        return Err("Invalid input len");
    }
    let key_chars: Vec<char> = input.chars().collect();

    const NUM_FOR_ASCII: [u8; 128] = [
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99, 99, 99, 99, 99, 99, 99, 99, 10, 11, 12, 99, 13, 14, 15, 99, 16, 17, 18, 19,
        20, 99, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99, 99, 99, 10, 11, 12, 99, 13, 14, 15, 99, 16, 17, 18, 19, 20, 99, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99,
    ];

    let (mut out_idx, mut in_idx) = (0usize, 0usize);
    let (mut shifts, mut next_byte) = (0u32, 0u32);
    let mut output: Vec<u8> = Vec::new();

    while in_idx < key_chars.len() {
        // ASCII decimal of public key char element
        let o = key_chars[in_idx] as usize;
        // Index of the char in CJDNS Base32 alphabet
        let b = NUM_FOR_ASCII[o];
        if b > 31 {
            return Err("Character does not suit base32 alphabet");
        }

        next_byte |= (b as u32) << shifts;
        shifts += 5;

        if shifts >= 8 {
            output.insert(out_idx, (next_byte & 0xff) as u8);
            shifts -= 8;
            next_byte >>= 8;
            out_idx += 1;
        }

        in_idx += 1
    }

    if shifts >= 5 || next_byte != 0 {
        return Err("The last char is too big");
    }

    Ok(output)
}
