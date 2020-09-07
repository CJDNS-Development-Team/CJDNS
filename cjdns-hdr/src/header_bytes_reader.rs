use std::slice::Iter;
use std::convert::TryFrom;

// todo 2 use slice
pub struct HeaderBytesReader<'a>(Iter<'a, u8>);

impl<'a> HeaderBytesReader<'a> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        if let Some(mut one_byte_vec) = self.read_bytes(1) {
            return one_byte_vec.pop();
        }
        None
    }

    pub fn read_u16_be(&mut self) -> Option<u16> {
        if let Some(two_bytes_vec) = self.read_bytes(2) {
            let two_bytes_array = <[u8; 2]>::try_from(two_bytes_vec.as_slice()).expect("wrong slice size");
            return Some(u16::from_be_bytes(two_bytes_array));
        }
        None
    }

    //TODO it is ineffective to construct Vec on each read - should return slice if possible
    fn read_bytes(&mut self, count: usize) -> Option<Vec<u8>> {
        let ret_bytes = self.0.by_ref().take(count).map(|&x| x).collect::<Vec<_>>();
        if ret_bytes.len() == count {
            return Some(ret_bytes)
        }
        None
    }
}

//TODO strange way to construct this reader - better use `new()` function
impl<'a> From<Iter<'a, u8>> for HeaderBytesReader<'a> {
    fn from(bytes_iter: Iter<'a, u8>) -> Self {
        HeaderBytesReader(bytes_iter)
    }
}