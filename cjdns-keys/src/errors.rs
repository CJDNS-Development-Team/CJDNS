use thiserror::Error;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum KeyError {
    #[error("Can not decode key string")]
    CannotDecode,

    #[error("Can not create from string")]
    CannotCreateFromString,

    #[error("Can not create ip6 from public key")]
    CannotCreateFromPublicKey,

    #[error("Can not create from bytes")]
    CannotCreateFromBytes,

    #[error("Can not parse node name")]
    CannotParseNodeName,
}

pub type Result<T> = std::result::Result<T, KeyError>;
