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
    pub(super) create_time: u64,
    pub(super) mut_state: Arc<Mutex<LinkStateMut>>,
}

#[derive(Clone, Debug)]
pub(super) struct LinkStateMut {
    pub(super) most_recent_ls_slot: u64,
    pub(super) mtu: u32,
    pub(super) flags: u8,
    pub(super) time: u64,
    pub(super) value: f64,
}

#[derive(Clone, Debug)]
pub(super) struct LinkStateEntry {
    pub(super) drops: u16,
    pub(super) lag: u16,
    pub(super) kb_recv: u32,
}

pub(super) fn mk_link(ann_peer: &PeerData, ann: &Announcement) -> Link {
    let ann_time = ann.header.timestamp;
    Link {
        label: ann_peer.label.as_ref().expect("zero label").clone(),
        encoding_form_number: ann_peer.encoding_form_number,
        peer_num: ann_peer.peer_num,
        link_state: Arc::new(Mutex::new(HashMap::new())),
        create_time: ann_time,
        mut_state: Arc::new(Mutex::new(LinkStateMut {
            most_recent_ls_slot: ann_time / 1000 / 10,
            mtu: ann_peer.mtu,
            flags: ann_peer.flags,
            time: ann_time,
            value: 0.0,
        })),
    }
}

impl Link {
    /// Each timeslot is 10 seconds, link state value halves every 3 minutes.
    pub(super) const DECAY_PER_TIMESLOT: f64 = 1.0 / 18.0;
}

impl LinkStateEntry {
    pub(super) fn ls_value(&self) -> f64 {
        // 0 lag is suspicious, probably not real data
        if self.lag == 0 {
            return 0.0;
        }

        let kb_recv = self.kb_recv as f64;
        let lag = self.lag as f64;
        let drops = self.drops as i32;

        // Higher kb received normally means lower risk that when we send data over the link,
        // it will be the data which finally pushes the link over the edge.
        // But rising latency is bad news.
        // By far the worst news is drops.
        kb_recv / (lag * f64::powi(2.0, drops))
    }
}
