//! Parsing and serialization helpers.

use std::convert::TryFrom;

type Result<T> = std::result::Result<T, ()>;

pub struct Reader<'a>(&'a [u8]);
pub struct Writer(Vec<u8>);

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader(data)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.take_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16_be(&mut self) -> Result<u16> {
        let bytes = self.take_bytes(2)?;
        let bytes_array = <[u8; 2]>::try_from(bytes).expect("invalid slice size");
        Ok(u16::from_be_bytes(bytes_array))
    }

    pub fn read_u32_be(&mut self) -> Result<u32> {
        let bytes = self.take_bytes(4)?;
        let bytes_array = <[u8; 4]>::try_from(bytes).expect("invalid slice size");
        Ok(u32::from_be_bytes(bytes_array))
    }

    pub fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self.take_bytes(8)?;
        let bytes_array = <[u8; 8]>::try_from(bytes).expect("invalid slice size");
        Ok(u64::from_be_bytes(bytes_array))
    }

    pub fn read_array_32(&mut self) -> Result<[u8; 32]> {
        let bytes_32_slice = self.take_bytes(32)?;
        let bytes_32_array = <[u8; 32]>::try_from(bytes_32_slice).expect("invalid slice size");
        Ok(bytes_32_array)
    }

    pub fn read_all_pure(&self) -> &[u8] {
        self.0
    }

    pub fn read_all_mut(&mut self) -> &[u8] {
        self.take_bytes(self.len()).expect("attempting to read data more than slice have")
    }

    pub fn take_bytes(&mut self, count: usize) -> Result<&[u8]> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader() {
        let bytes = vec![0u8; 64];
        let mut reader = Reader::new(&bytes);

        let array_32 = reader.read_array_32().expect("bytes are read out");
        assert_eq!(array_32, [0; 32]);
        let num64 = reader.read_u64_be().expect("bytes are read out");
        assert_eq!(num64.to_be_bytes(), [0; 8]);
        let num32 = reader.read_u32_be().expect("bytes are read out");
        assert_eq!(num32.to_be_bytes(), [0; 4]);
        let num16 = reader.read_u16_be().expect("bytes are read out");
        assert_eq!(num16.to_be_bytes(), [0; 2]);
        let num8 = reader.read_u8().expect("bytes are read out");
        assert_eq!(num8, 0);
        // checking read out of bounds
        assert!(reader.take_bytes(20).is_err());
        // reading last bytes
        reader.take_bytes(17).expect("bytes are read out");
        assert_eq!(reader.len(), 0);
    }

    #[test]
    fn test_writer() {
        let initial_capacity = 64;
        let mut writer = Writer::with_capacity(64);

        writer.write_u8(0);
        writer.write_u16_be(0);
        writer.write_u32_be(0);
        writer.write_u64_be(0);
        writer.write_slice(&[0; 49]);

        let bytes = writer.into_vec();
        assert_eq!(bytes.len(), initial_capacity);
        assert_eq!(bytes, vec![0; initial_capacity]);
    }

    #[test]
    fn test_read_all() {
        let bytes = vec![0; 32];
        let mut reader = Reader::new(&bytes);

        assert_eq!(bytes.as_slice(), reader.read_all_pure());
        let _ = reader.read_u16_be();
        assert_eq!(&bytes[2..], reader.read_all_pure());
        let _ = reader.read_u16_be();
        assert_eq!(&bytes[4..], reader.read_all_mut());
        assert_eq!(0, reader.len())
    }
}
