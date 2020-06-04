use std::error;
use std::fmt;

use cjdns_entities::LabelT;

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(Debug, PartialEq)]
pub enum Error {
    LabelTooLong,
    ZeroLabel,
    NotEnoughArguments,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::LabelTooLong => write!(f, "Label is too long"),
            Error::ZeroLabel => write!(f, "Label is zero"),
            Error::NotEnoughArguments => write!(f, "Not enough arguments"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

pub fn splice<L: LabelT>(labels: &[L]) -> Result<L> {
    if labels.len() < 2 {
        return Err(Error::NotEnoughArguments);
    }

    let mut result = labels[0];
    if result.highest_set_bit().is_none() {
        return Err(Error::ZeroLabel);
    }

    for addon in &labels[1..] {
        match addon.highest_set_bit() {
            None => return Err(Error::ZeroLabel),

            Some(addon_bitlen) => {
                if result.highest_set_bit().unwrap() + addon_bitlen > L::max_bit_size() - 1 {
                    return Err(Error::LabelTooLong);
                }

                result = ((result ^ L::from_u32(1u32)) << addon_bitlen) ^ *addon;
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use cjdns_entities::Label;

    fn l(v: &str) -> Label {
        Label::try_from(v).unwrap()
    }

    #[test]
    fn test_splice() {
        assert_eq!(splice::<Label>(&[]), Err(Error::NotEnoughArguments));
        assert_eq!(
            splice(&[l("0000.0000.0000.0015")]),
            Err(Error::NotEnoughArguments)
        );
        assert_eq!(
            splice(&[l("0000.0000.0000.0015"), l("0000.0000.0000.0000")]),
            Err(Error::ZeroLabel)
        );
        assert_eq!(
            splice(&[l("0000.0000.0000.0000"), l("0000.0000.0000.0013")]),
            Err(Error::ZeroLabel)
        );

        assert_eq!(
            splice(&[l("0000.0000.0000.0015"), l("0000.0000.0000.0013")]),
            Ok(l("0000.0000.0000.0153"))
        );
    }

    #[test]
    fn test_splice_long_label() {
        assert_eq!(
            splice(&[l("0200.0000.0000.1111"), l("0000.0000.0000.0005")]),
            Ok(l("0800.0000.0000.4445"))
        );

        assert_eq!(
            splice(&[l("0400.0000.0000.1111"), l("0000.0000.0000.0005")]),
            Err(Error::LabelTooLong)
        );
    }
}
