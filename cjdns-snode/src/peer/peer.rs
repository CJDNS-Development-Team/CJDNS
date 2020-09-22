//! Peer supernode connection

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::message::Message;

/// Peer supernode.
///
/// This type is cloneable, each copy shares the same underlying data and can be used to send messages and query information.
#[derive(Clone)]
pub struct Peer {
    pub(super) id: u64,
    pub(super) addr: String,
    pub(super) peer_type: PeerType,
    pub(super) last_msg_time: Arc<RwLock<Instant>>,
    outstanding_reqs: Arc<Mutex<HashSet<u64>>>,
    msg_queue: mpsc::Sender<Message>, // Cloneable sender
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum PeerType { Incoming, Outgoing }

/// Error type for the situation when peer connection already closed while trying to do something with like (like send a message).
#[derive(thiserror::Error, Debug)]
#[error("Connection closed")]
pub(super) struct PeerConnectionClosed;

impl Peer {
    pub(super) fn new(id: u64, addr: String, peer_type: PeerType, msg_queue: mpsc::Sender<Message>) -> Self {
        Peer {
            id,
            addr,
            peer_type,
            last_msg_time: Arc::new(RwLock::new(Instant::now())),
            outstanding_reqs: Arc::new(Mutex::new(HashSet::new())),
            msg_queue,
        }
    }

    pub(super) fn get_outstanding_reqs_count(&self) -> usize {
        self.outstanding_reqs.lock().len()
    }

    pub(super) async fn send_msg(&mut self, msg: Message) -> Result<(), PeerConnectionClosed> {
        self.msg_queue.send(msg).await.map_err(|_| PeerConnectionClosed)
    }

    pub(super) fn add_pending_req(&self, seq: u64) {
        self.outstanding_reqs.lock().insert(seq);
    }

    pub(super) fn complete_req(&self, seq: u64) -> bool {
        self.outstanding_reqs.lock().remove(&seq)
    }
}
