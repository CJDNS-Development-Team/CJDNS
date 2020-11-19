//! Parsing and serialization helpers.
pub use reader::{ExpectedSize, Reader};
pub use writer::Writer;

mod reader {
    use std::convert::TryFrom;

    type Result<T> = std::result::Result<T, InsufficientBuffer>;

    /// Buffer reader
    pub struct Reader<'a>(&'a [u8]);
    #[derive(Debug)]
    /// Error marking try to read more than buffer size.
    pub struct InsufficientBuffer;
    /// Error that is returned when expected size bounds are not met. Read more in `Reader::read` docs.
    pub struct ReadError;

    /// Expected by user size of buffer.
    pub enum ExpectedSize {
        /// `Reader` must have exact size, equal to associated value
        Exact(usize),
        /// `Reader` length must be not less than associated value
        NotLessThan(usize),
    }

    impl<'a> Reader<'a> {
        /// Instantiates `Reader`.
        pub fn new(data: &'a [u8]) -> Self {
            Reader(data)
        }

        /// Reads bytes in accordance to logic implemented in `job`.
        ///
        /// If `expected_size` check fails (i.e. readers size does not apply to expected condition), `ReaderError` is returned.
        ///
        /// # Panics
        ///
        /// `job` closure is used to encapsulate multiple reads from `Reader`. Data reads in `job` must be infallible: they should coordinate with the
        /// expected size. So if too much than could be or less than stated in `expected_size` was read, it finishes with panic.
        pub fn read<R, F: FnOnce(&mut Self) -> Result<R>>(&mut self, expected_size: ExpectedSize, job: F) -> std::result::Result<R, ReadError> {
            let len_before_read = self.len();
            match expected_size {
                ExpectedSize::Exact(count) => {
                    if self.len() != count {
                        return Err(ReadError);
                    }
                    let res = job(self).expect("reading data more than could be");
                    assert_eq!(self.len(), len_before_read - count, "reading data less than stated");
                    Ok(res)
                }
                ExpectedSize::NotLessThan(count) => {
                    if self.len() < count {
                        return Err(ReadError);
                    }
                    let res = job(self).expect("reading data more than could be");
                    assert!(len_before_read - count >= self.len(), "reading data less than stated");
                    Ok(res)
                }
            }
        }

        /// Reads u8
        pub fn read_u8(&mut self) -> Result<u8> {
            let bytes = self.read_slice(1)?;
            Ok(bytes[0])
        }

        /// Reads big endian u16
        pub fn read_u16_be(&mut self) -> Result<u16> {
            let bytes = self.read_slice(2)?;
            let bytes_array = <[u8; 2]>::try_from(bytes).expect("invalid slice size");
            Ok(u16::from_be_bytes(bytes_array))
        }

        /// Reads big endian u32
        pub fn read_u32_be(&mut self) -> Result<u32> {
            let bytes = self.read_slice(4)?;
            let bytes_array = <[u8; 4]>::try_from(bytes).expect("invalid slice size");
            Ok(u32::from_be_bytes(bytes_array))
        }

        /// Reads big endian u64
        pub fn read_u64_be(&mut self) -> Result<u64> {
            let bytes = self.read_slice(8)?;
            let bytes_array = <[u8; 8]>::try_from(bytes).expect("invalid slice size");
            Ok(u64::from_be_bytes(bytes_array))
        }

        /// Reads `[u8; 32]` array.
        pub fn read_array_32(&mut self) -> Result<[u8; 32]> {
            let bytes_32_slice = self.read_slice(32)?;
            let bytes_32_array = <[u8; 32]>::try_from(bytes_32_slice).expect("invalid slice size");
            Ok(bytes_32_array)
        }

        /// Peeks remainder without mutating readers state
        pub fn peek_remainder(&self) -> &'a [u8] {
            self.0
        }

        /// Returns remainder mutating readers state.
        pub fn read_remainder(&mut self) -> &'a [u8] {
            self.read_slice(self.len()).expect("attempting to read data more than slice have")
        }

        /// Skips `count` amount of data.
        pub fn skip(&mut self, count: usize) -> Result<()> {
            let _ = self.read_slice(count)?;
            Ok(())
        }

        /// Reads `count` values.
        pub fn read_slice(&mut self, count: usize) -> Result<&'a [u8]> {
            if self.len() < count {
                return Err(InsufficientBuffer);
            }
            let (ret_bytes, rest_bytes) = self.0.split_at(count);
            self.0 = rest_bytes;
            Ok(ret_bytes)
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
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
            let bytes = (0..64).collect::<Vec<u8>>();
            let mut reader = Reader::new(&bytes);

            let num8 = reader.read_u8().expect("bytes are read out");
            assert_eq!(num8, 0);
            let num16 = reader.read_u16_be().expect("bytes are read out");
            assert_eq!(num16.to_be_bytes(), [1, 2]);
            let num32 = reader.read_u32_be().expect("bytes are read out");
            assert_eq!(num32.to_be_bytes(), [3, 4, 5, 6]);
            let num64 = reader.read_u64_be().expect("bytes are read out");
            assert_eq!(num64.to_be_bytes(), [7, 8, 9, 10, 11, 12, 13, 14]);
            let array_32 = reader.read_array_32().expect("bytes are read out");
            assert_eq!(array_32.to_vec(), (15..47).collect::<Vec<u8>>());
            // checking read out of bounds
            assert!(reader.read_slice(20).is_err());
            // reading last bytes
            reader.read_slice(17).expect("bytes are read out");
            assert_eq!(reader.len(), 0);
        }

        #[test]
        fn test_remainder() {
            let bytes = (0..32).collect::<Vec<u8>>();
            let mut reader = Reader::new(&bytes);

            assert_eq!(&bytes, &reader.peek_remainder());
            let _ = reader.read_u16_be();
            assert_eq!(&bytes[2..], reader.peek_remainder());
            let _ = reader.read_u16_be();
            assert_eq!(&bytes[4..], reader.read_remainder());
            assert_eq!(0, reader.len())
        }

        #[test]
        fn test_custom_read() {
            let bytes = vec![0; 32];
            let mut reader = Reader::new(&bytes);

            assert!(reader.read(ExpectedSize::Exact(35), |_| Ok(())).is_err());
            assert!(reader.read(ExpectedSize::NotLessThan(35), |_| Ok(())).is_err());
        }

        #[test]
        #[should_panic]
        fn test_read_more_for_exact() {
            let bytes = vec![0; 32];
            let mut reader = Reader::new(&bytes);
            // panics: trying to read more than stated
            let _ = reader.read(ExpectedSize::Exact(32), |r| {
                let invalid_res = r.read_slice(35)?;
                Ok(invalid_res)
            });
        }

        #[test]
        #[should_panic]
        fn test_read_less_for_exact() {
            let bytes = vec![0; 32];
            let mut reader = Reader::new(&bytes);
            // panics: trying to read less than stated
            let _ = reader.read(ExpectedSize::Exact(32), |r| {
                let invalid_res = r.read_slice(20)?;
                Ok(invalid_res)
            });
        }

        #[test]
        #[should_panic]
        fn test_read_more_for_not_less_than() {
            let bytes = vec![0; 32];
            let mut reader = Reader::new(&bytes);
            // panics: trying to read more than stated
            let _ = reader.read(ExpectedSize::NotLessThan(32), |r| {
                let invalid_res = r.read_slice(35)?;
                Ok(invalid_res)
            });
        }

        #[test]
        #[should_panic]
        fn test_read_less_for_not_less_than() {
            let bytes = vec![0; 32];
            let mut reader = Reader::new(&bytes);
            // panics: trying to read less than stated
            let _ = reader.read(ExpectedSize::NotLessThan(32), |r| {
                let invalid_res = r.read_slice(20)?;
                Ok(invalid_res)
            });
        }
    }
}

mod writer {
    /// Buffer writer. Wrapper over `Vec<u8`.
    pub struct Writer(Vec<u8>);

    impl Writer {
        /// Instantiates new writer.
        pub fn new() -> Self {
            Self(Vec::new())
        }

        /// Instantiates writer with provided `capacity`.
        pub fn with_capacity(capacity: usize) -> Self {
            Self(Vec::with_capacity(capacity))
        }

        /// Converts `Writer` into `Vec<u8>`.
        pub fn into_vec(self) -> Vec<u8> {
            self.0
        }

        /// Writes u8 to buffer.
        pub fn write_u8(&mut self, data: u8) {
            self.write_slice(&[data]);
        }

        /// Writes big endian u16 to buffer.
        pub fn write_u16_be(&mut self, data: u16) {
            self.write_slice(&data.to_be_bytes());
        }

        /// Writes big endian u32 to buffer.
        pub fn write_u32_be(&mut self, data: u32) {
            self.write_slice(&data.to_be_bytes())
        }

        /// Writes big endian 64 to buffer.
        pub fn write_u64_be(&mut self, data: u64) {
            self.write_slice(&data.to_be_bytes());
        }

        /// Writes slice to buffer.
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
            writer.write_u16_be(258);
            writer.write_u32_be(50595078);
            writer.write_u64_be(506664896818842894);

            let data = (15..64).collect::<Vec<u8>>();
            writer.write_slice(&data);

            let bytes = writer.into_vec();
            assert_eq!(bytes.len(), initial_capacity);
            assert_eq!(bytes, (0..64).collect::<Vec<u8>>());
        }
    }
}
