#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    CannotDecode,
    CannotCreateFromString,
    CannotCreateFromPublicKey,
    CannotCreateFromBytes,
    CannotParseNodeName,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CannotDecode => write!(f, "Can not decode key string"),
            Error::CannotCreateFromString => write!(f, "Can not create from string"),
            Error::CannotCreateFromPublicKey => write!(f, "Can not create ip6 from public key"),
            Error::CannotCreateFromBytes => write!(f, "Can not create from bytes"),
            Error::CannotParseNodeName => write!(f, "Can not parse node name"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
