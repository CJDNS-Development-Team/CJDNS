//! Parsing and serialization helpers.
pub use reader::Reader;
pub use writer::Writer;

mod reader {
    use std::convert::TryFrom;

    type Result<T> = std::result::Result<T, ReaderError>;

    pub struct Reader<'a>(&'a [u8]);
    #[derive(Debug)]
    pub struct ReaderError;

    impl<'a> Reader<'a> {
        pub fn new(data: &'a [u8]) -> Self {
            Reader(data)
        }

        // Reads bytes in accordance to logic implemented in `work`. The `work` closure calls
        // `Reader` methods reading bytes safely without getting out of bounds. That is because
        // `read` method compares reading bytes array size with `count`, which is intended to read amount of bytes.
        pub fn read<R, C: FnOnce(&mut Self) -> Result<R>>(&mut self, count: usize, work: C) -> Result<R> {
            if self.len() != count {
                return Err(ReaderError)
            }
            // actually never fails because of len check upper
            // could be Ok(work(self).expect("invalid reading data size"))
            work(self)
        }

        pub fn read_u8(&mut self) -> Result<u8> {
            let bytes = self.read_bytes(1)?;
            Ok(bytes[0])
        }

        pub fn read_u16_be(&mut self) -> Result<u16> {
            let bytes = self.read_bytes(2)?;
            let bytes_array = <[u8; 2]>::try_from(bytes).expect("invalid slice size");
            Ok(u16::from_be_bytes(bytes_array))
        }

        pub fn read_u32_be(&mut self) -> Result<u32> {
            let bytes = self.read_bytes(4)?;
            let bytes_array = <[u8; 4]>::try_from(bytes).expect("invalid slice size");
            Ok(u32::from_be_bytes(bytes_array))
        }

        pub fn read_u64_be(&mut self) -> Result<u64> {
            let bytes = self.read_bytes(8)?;
            let bytes_array = <[u8; 8]>::try_from(bytes).expect("invalid slice size");
            Ok(u64::from_be_bytes(bytes_array))
        }

        pub fn read_array_32(&mut self) -> Result<[u8; 32]> {
            let bytes_32_slice = self.read_bytes(32)?;
            let bytes_32_array = <[u8; 32]>::try_from(bytes_32_slice).expect("invalid slice size");
            Ok(bytes_32_array)
        }

        pub fn pick_remainder(&self) -> &[u8] {
            self.0
        }

        pub fn read_remainder(&mut self) -> &[u8] {
            self.read_bytes(self.len()).expect("attempting to read data more than slice have")
        }

        pub fn read_bytes(&mut self, count: usize) -> Result<&[u8]> {
            if self.len() < count {
                return Err(ReaderError);
            }
            let (ret_bytes, rest_bytes) = self.0.split_at(count);
            self.0 = rest_bytes;
            Ok(ret_bytes)
        }

        fn len(&self) -> usize {
            self.0.len()
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
            assert!(reader.read_bytes(20).is_err());
            // reading last bytes
            reader.read_bytes(17).expect("bytes are read out");
            assert_eq!(reader.len(), 0);
        }

        #[test]
        fn test_read_all() {
            let bytes = vec![0; 32];
            let mut reader = Reader::new(&bytes);

            assert_eq!(bytes.as_slice(), reader.pick_remainder());
            let _ = reader.read_u16_be();
            assert_eq!(&bytes[2..], reader.pick_remainder());
            let _ = reader.read_u16_be();
            assert_eq!(&bytes[4..], reader.read_remainder());
            assert_eq!(0, reader.len())
        }
    }
}

mod writer {
    pub struct Writer(Vec<u8>);

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
    }
}
