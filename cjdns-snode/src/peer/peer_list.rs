//! Peer supernode list

use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::message::Message;
use crate::peer::{Peer, PeerType};
use crate::utils::seq::Seq;

pub(super) struct PeerList {
    peer_id_seq: Seq,
    peers: RwLock<Vec<Peer>>,
}

impl PeerList {
    pub(super) fn new() -> Self {
        PeerList {
            peer_id_seq: Seq::new(0),
            peers: RwLock::new(Vec::new()),
        }
    }

    pub(super) fn list<T, F: FnMut(&Peer) -> T>(&self, f: F) -> Vec<T> {
        self.peers.read().iter().map(f).collect()
    }

    pub(super) fn create_peer(&self, peer_type: PeerType, addr: String, msg_queue: mpsc::Sender<Message>) -> Peer {
        let peer_id = self.peer_id_seq.next();
        let peer = Peer::new(peer_id, addr, peer_type, msg_queue);
        self.peers.write().push(peer.clone());
        peer
    }

    pub(super) fn remove_peer(&self, id: u64) {
        self.peers.write().retain(|p| p.id != id);
    }

    pub(super) fn get_timed_out_peers(&self, drop_after: Duration, ping_after: Duration) -> (Vec<Peer>, Vec<Peer>) {
        let (mut ping_list, mut drop_list) = (Vec::new(), Vec::new());

        // Check last message time for every peer
        let now = Instant::now();
        for peer in self.peers.read().iter().cloned() {
            let lag = now - *peer.last_msg_time.read();
            if lag > drop_after {
                drop_list.push(peer);
            } else if lag > ping_after {
                ping_list.push(peer);
            }
        }

        (ping_list, drop_list)
    }
}
