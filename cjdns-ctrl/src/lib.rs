//! Parsing/serializing CTRL messages

pub use cjdns_bytes::{ParseError, SerializeError};

pub enum CtrlMessage {
    //TODO
}

impl CtrlMessage {
    pub fn parse() -> Result<Self, ParseError> {
        todo!()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        todo!()
    }
}