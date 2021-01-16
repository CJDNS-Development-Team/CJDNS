//! Utility functions

pub(crate) fn vec_to_array32(vec: Vec<u8>) -> [u8; 32] {
    let mut array = [0u8; 32];
    array.copy_from_slice(&vec);
    array
}

pub(crate) fn vec_to_array16(vec: Vec<u8>) -> [u8; 16] {
    slice_to_array16(&vec)
}

pub(crate) fn slice_to_array16(slice: &[u8]) -> [u8; 16] {
    let mut array = [0u8; 16];
    array.copy_from_slice(slice);
    array
}

pub(crate) fn debug_fmt<T: AsRef<[u8]>>(bytes: T, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let s = hex::encode(bytes);
    f.write_str(&s)
}
