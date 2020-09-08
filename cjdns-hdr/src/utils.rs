// TODO tests

use std::convert::TryFrom;

type ResultReader<T> = Result<T, ()>;

pub(crate) struct Reader<'a>(&'a [u8]);
pub(crate) struct Writer(Vec<u8>);

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader(data)
    }

    pub fn read_u8(&mut self) -> ResultReader<u8> {
        let bytes = self.take_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16_be(&mut self) -> ResultReader<u16> {
        let bytes = self.take_bytes(2)?;
        let bytes_array = <[u8; 2]>::try_from(bytes).expect("invalid slice size");
        Ok(u16::from_be_bytes(bytes_array))
    }

    pub fn read_u32_be(&mut self) -> ResultReader<u32> {
        let bytes = self.take_bytes(4)?;
        let bytes_array = <[u8; 4]>::try_from(bytes).expect("invalid slice size");
        Ok(u32::from_be_bytes(bytes_array))
    }

    pub fn read_u64_be(&mut self) -> ResultReader<u64> {
        let bytes = self.take_bytes(8)?;
        let bytes_array = <[u8; 8]>::try_from(bytes).expect("invalid slice size");
        Ok(u64::from_be_bytes(bytes_array))
    }

    pub fn read_array_32(&mut self) -> ResultReader<[u8; 32]> {
        let bytes_32_slice = self.take_bytes(32)?;
        let bytes_32_array = <[u8; 32]>::try_from(bytes_32_slice).expect("invalid slice size");
        Ok(bytes_32_array)
    }

    pub fn take_bytes(&mut self, count: usize) -> ResultReader<&[u8]> {
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
        self.write_slice(&[data]);
    }

    pub fn write_u16_be(&mut self, data: u16) {
        self.write_slice(&data.to_be_bytes());
    }

    pub fn write_u32_be(&mut self, data: u32) {
        self.write_slice(&data.to_be_bytes())
    }

    pub fn write_u64_be(&mut self, data: u64) {
        self.write_slice(&data.to_be_bytes());
    }

    pub fn write_slice(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}
