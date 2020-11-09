//! Link state.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use cjdns_ann::{Announcement, PeerData};
use cjdns_core::RoutingLabel;

#[derive(Clone)]
pub(super) struct Link {
    pub(super) label: RoutingLabel<u32>,
    pub(super) encoding_form_number: u8,
    pub(super) peer_num: u16,
    pub(super) link_state: Arc<Mutex<HashMap<u64, LinkStateEntry>>>,
    pub(super) mut_state: Arc<Mutex<LinkStateMut>>
}

#[derive(Clone, Debug)]
pub(super) struct LinkStateMut {
    pub(super) mtu: u32,
    pub(super) flags: u8,
    pub(super) time: u64,
    pub(super) cost: u32,
}

#[derive(Clone, Debug)]
pub(super) struct LinkStateEntry {
    pub(super) drops: u16,
    pub(super) lag: u16,
    pub(super) kb_recv: u32,
}

pub(super) fn mk_link(ann_peer: &PeerData, ann: &Announcement) -> Link {
    Link {
        label: ann_peer.label.as_ref().expect("zero label").clone(),
        encoding_form_number: ann_peer.encoding_form_number,
        peer_num: ann_peer.peer_num,
        link_state: Arc::new(Mutex::new(HashMap::new())),
        mut_state: Arc::new(Mutex::new(
            LinkStateMut {
                mtu: ann_peer.mtu,
                flags: ann_peer.flags,
                time: ann.header.timestamp,
                cost: 0,
            }
        ))
    }
}
