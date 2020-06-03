use std::error;
use std::fmt;

use cjdns_entities::{Label, LabelT};

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug)]
pub enum Error {
    LabelTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::LabelTooLong => write!(f, "Label is too long"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

pub fn splice<L: LabelT>(labels: &[L]) -> Result<L> {
    Ok(labels[0] ^ labels[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(
            splice(&[Label::new(3), Label::new(1), Label::new(5)]).unwrap(),
            Label::new(2)
        );
    }
}
