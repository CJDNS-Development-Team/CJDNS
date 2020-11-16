//! Announcement hash computation.

use std::sync::Arc;

use sodiumoxide::crypto::hash::sha512;

use cjdns_ann::AnnHash;

use crate::server::nodes::Node;

pub(super) fn node_announcement_hash(node: Option<Arc<Node>>, debug_noisy: bool) -> AnnHash {
    let mut carry = sha512::Digest([0; 64]);
    let mut state = 0;
    if let Some(node) = node {
        let mut node_mut = node.mut_state.write();
        state = node_mut.announcements.len();
        for ann in node_mut.announcements.iter().rev() {
            let mut hash = sha512::State::new();
            hash.update(carry.as_ref());
            hash.update(&ann.binary);
            carry = hash.finalize();
        }
        node_mut.state_hash = Some(AnnHash::from_digest(carry));
    }
    if debug_noisy {
        debug!("node announcement hash - {}, state - {}", hex::encode(carry), state);
    }
    AnnHash::from_digest(carry)
}
