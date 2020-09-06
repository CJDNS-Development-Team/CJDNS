use std::slice::Iter;
use std::convert::TryFrom;

// todo 2 use Vec?
pub struct HeaderBytesReader<'a>(Iter<'a, u8>);

impl<'a> HeaderBytesReader<'a> {

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn read_be_u8(&mut self) -> Option<u8> {
        if let Some(mut one_byte_vec) = self.read_n_bytes(1) {
            return one_byte_vec.pop();
        }
        None
    }

    pub fn read_be_u16(&mut self) -> Option<u16> {
        if let Some(two_bytes_vec) = self.read_n_bytes(2) {
            let two_bytes_array = <[u8; 2]>::try_from(two_bytes_vec.as_slice()).expect("wrong slice size");
            return Some(u16::from_be_bytes(two_bytes_array));
        }
        None

    }

    fn read_n_bytes(&mut self, bytes_num: usize) -> Option<Vec<u8>> {
        let ret_bytes = self.0.by_ref().take(bytes_num).map(|&x| x).collect::<Vec<_>>();
        if ret_bytes.len() == bytes_num {
            return Some(ret_bytes)
        }
        None
    }
}

impl<'a> From<Iter<'a, u8>> for HeaderBytesReader<'a> {
    fn from(bytes_iter: Iter<'a, u8>) -> Self {
        HeaderBytesReader(bytes_iter)
    }
}