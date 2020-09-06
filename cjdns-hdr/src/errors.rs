#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HeaderError {
    CannotParse(&'static str),
    CannotSerialize(&'static str),
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HeaderError::CannotSerialize(reason) => write!(f, "Can't serialize header: {}", reason),
            HeaderError::CannotParse(reason) => write!(f, "Can't parse header bytes: {}", reason),
        }
    }
}

impl std::error::Error for HeaderError {}