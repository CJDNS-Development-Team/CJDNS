use cjdns_entities::{LabelT, Label};


pub fn splice<L: LabelT>(labels: &[L]) -> L {
    labels[0] ^ labels[1]
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(splice(&[Label::new(3), Label::new(1), Label::new(5)]),
                   Label::new(2));
    }
}
