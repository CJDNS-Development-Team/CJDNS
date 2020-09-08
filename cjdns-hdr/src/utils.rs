// TODO consider на std::io::Cursor
// TODO tests

use std::convert::TryFrom;

type ResultReader<T> = Result<T, ()>;

pub struct Reader<'a>(&'a [u8]);
pub struct Writer(Vec<u8>);

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader(data)
    }

    pub fn read_u8(&mut self) -> ResultReader<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16_be(&mut self) -> ResultReader<u16> {
        let bytes = self.read_bytes(2)?;
        let bytes_array = <[u8; 2]>::try_from(bytes).expect("wrong slice size");
        Ok(u16::from_be_bytes(bytes_array))
    }

    pub fn read_u64_be(&mut self) -> ResultReader<u64> {
        let bytes = self.read_bytes(8)?;
        let bytes_array = <[u8; 8]>::try_from(bytes).expect("wrong slice size");
        Ok(u64::from_be_bytes(bytes_array))
    }

    fn read_bytes(&mut self, count: usize) -> ResultReader<&[u8]> {
        if self.len() < count {
            return Err(());
        }
        let (ret_bytes, rest_bytes) = self.0.split_at(count);
        self.0 = rest_bytes;
        Ok(ret_bytes)
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Writer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn write_u8(&mut self, data: u8) {
        self.0.extend_from_slice(&[data]);
    }

    // TODO maybe use num crate to make generic write?
    pub fn write_u16_be(&mut self, data: u16) {
        self.0.extend_from_slice(&data.to_be_bytes())
    }

    pub fn write_u64_be(&mut self, data: u64) {
        self.0.extend_from_slice(&data.to_be_bytes())
    }
}
