use thiserror::Error;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum HeaderError {
    #[error("Can't serialize header: {0}")]
    CannotParse(&'static str),

    #[error("Can't parse header bytes: {0}")]
    CannotSerialize(&'static str),
}

pub(crate) type Result<T> = std::result::Result<T, HeaderError>;
