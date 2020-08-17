//! Path hop.

use crate::{EncodingScheme, LabelBits, RoutingLabel};

#[derive(Debug, PartialEq, Eq)]
pub struct PathHop<'a, L: LabelBits> {
    pub label_p: Option<RoutingLabel<L>>,
    pub label_n: Option<RoutingLabel<L>>,
    pub encoding_scheme: &'a EncodingScheme,
}

impl<'a, L: LabelBits> PathHop<'a, L> {
    pub fn new(label_p: Option<RoutingLabel<L>>, label_n: Option<RoutingLabel<L>>, encoding_scheme: &'a EncodingScheme) -> Self {
        PathHop {
            label_p,
            label_n,
            encoding_scheme,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{EncodingScheme, LabelBits, PathHop, RoutingLabel, schemes};

    fn hop<L: LabelBits>(label_p_bits: L, label_n_bits: L, encoding_scheme: &EncodingScheme) -> PathHop<L> {
        let label_p = RoutingLabel::try_new(label_p_bits);
        let label_n = RoutingLabel::try_new(label_n_bits);
        PathHop::new(label_p, label_n, encoding_scheme)
    }

    #[test]
    fn path_hop_creation() {
        assert_eq!(
            hop(2_u64, 2_u64, &schemes::V358),
            PathHop {
                label_p: Some(RoutingLabel::try_new(2_u64).expect("bad test data")),
                label_n: Some(RoutingLabel::try_new(2_u64).expect("bad test data")),
                encoding_scheme: &schemes::V358,
            }
        );
        assert_eq!(
            hop(0_u64, 2_u64, &schemes::V358),
            PathHop {
                label_p: None,
                label_n: Some(RoutingLabel::try_new(2_u64).expect("bad test data")),
                encoding_scheme: &schemes::V358,
            }
        );
        assert_eq!(
            hop(3_u64, 0_u64, &schemes::V358),
            PathHop {
                label_p: Some(RoutingLabel::try_new(3_u64).expect("bad test data")),
                label_n: None,
                encoding_scheme: &schemes::V358,
            }
        );
    }
}
