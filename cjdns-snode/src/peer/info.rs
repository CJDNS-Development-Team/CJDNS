//! Info about connections to peer supernodes

use crate::peer::{Peer, PeerList, Peers};

pub struct PeersInfo {
    pub peers: Vec<PeerInfo>,
    pub announcements: usize,
    pub ann_by_hash_len: usize,
}

pub struct PeerInfo {
    pub addr: String,
    pub outstanding_requests: usize,
    pub msgs_on_wire: usize,
    pub msg_queue: usize,
}

impl Peers {
    pub fn get_info(&self) -> PeersInfo {
        let (hash_count, ann_count) = self.anns.lock().info();
        PeersInfo {
            peers: self.peers.info(),
            announcements: hash_count,
            ann_by_hash_len: ann_count,
        }
    }
}

impl PeerList {
    fn info(&self) -> Vec<PeerInfo> {
        self.list(|peer| peer.info())
    }
}

impl Peer {
    fn info(&self) -> PeerInfo {
        PeerInfo {
            addr: "".to_string(), //TODO self.socket._socket.remoteAddress
            outstanding_requests: self.get_outstanding_reqs_count(),
            msgs_on_wire: 0, //TODO useless?
            msg_queue: 0, //self.msg_queue.len(), //TODO possible?
        }
    }
}
