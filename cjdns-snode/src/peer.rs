//! Connecting to other supernodes

use std::time::{Duration, Instant};

use anyhow::Error;
use futures::{Future, SinkExt, StreamExt};
use http::Uri;
use parking_lot::Mutex;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tungstenite as websocket;

use cjdns_ann::AnnHash;

use crate::message::{Message, MessageData};
use crate::msg;
use crate::server::websock::WebSock;
use crate::utils::rand::seed;
use crate::utils::seq::Seq;

pub(crate) use self::ann_list::AnnData;
use self::ann_list::AnnList;
pub use self::info::{PeerInfo, PeersInfo};
pub use self::peer::Peer;
use self::peer::PeerType;
use self::peer_list::PeerList;

mod ann_list;
mod info;
mod peer;
mod peer_list;
mod ping;

pub struct Peers {
    peers: PeerList,
    anns: Mutex<AnnList>,
    msg_id_seq: Seq,
    announce_tx: mpsc::Sender<AnnData>,
}

impl Peers {
    const VERSION: u64 = 1;
}

pub fn create_peers() -> (Peers, mpsc::Receiver<AnnData>) {
    const QUEUE_SIZE: usize = 256;
    let (tx, rx) = mpsc::channel(QUEUE_SIZE);
    let peers = Peers::new(tx);
    (peers, rx)
}

impl Peers {
    /// Create new instance of Peers + announce sender
    fn new(ann_tx: mpsc::Sender<AnnData>) -> Self {
        Peers {
            peers: PeerList::new(),
            anns: Mutex::new(AnnList::new()),
            msg_id_seq: Seq::new(seed()),
            announce_tx: ann_tx,
        }
    }

    /// Asynchronously start connecting to the specified peer supernode.
    /// If the connection can't be established or closed by the remote side,
    /// it will be reconnected automatically after a delay.
    pub async fn connect_to(&self, uri: Uri) {
        debug!("Connecting to {}", uri);
        loop {
            let res = websocket::connect_async(&uri).await;

            let sucessfully_connected = res.is_ok();

            match res {
                Ok((ws_stream, _)) => {
                    info!("Connected to {}", uri);
                    let ipv6_addr = {
                        // Trim brackets: '[1:2:3:4]' -> '1:2:3:4'
                        let host = uri.host().expect("host");
                        let n = host.len();
                        if n >= 2 && host.starts_with('[') && host.ends_with(']') {
                            &host[1..n - 2]
                        } else {
                            host
                        }
                    }
                    .to_string();
                    let res = self.outgoing(ipv6_addr, ws_stream).await;
                    if let Err(e) = res {
                        debug!("Error reading from peer: {}", e);
                    }
                    info!("Disconnected from {}", uri);
                }
                Err(e) => {
                    trace!("> {} ERROR: {}", uri, e);
                }
            }

            let delay = if sucessfully_connected {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(10)
            };
            time::delay_for(delay).await;
        }
    }

    pub async fn accept_incoming_connection(&self, from_ipv6: String, ws_stream: impl WebSock) -> Result<(), Error> {
        info!("Incoming connection from {}", from_ipv6);
        self.incoming(from_ipv6, ws_stream).await
    }

    pub async fn add_ann(&self, hash: AnnHash, binary: AnnData) {
        {
            let mut anns = self.anns.lock();
            if anns.hash_list().iter().any(|h| *h == hash) {
                warn!("Tried to add hash [{}] multiple times", hex::encode(hash.bytes()));
                return;
            }
            anns.add(hash.clone(), binary);
        }
        for mut peer in self.peers.list(|peer| peer.clone()) {
            if peer.peer_type == PeerType::Incoming {
                let _ = peer.send_msg(msg![0, "INV", 0 => hashes = &[ hash.clone() ]]).await;
            }
        }
    }

    pub fn del_ann(&self, hash: &AnnHash) {
        self.anns.lock().remove(hash);
    }

    /// Handle incoming WebSocket connection and process it until closed.
    /// This async fn completes when the connection is closed, so spawn a task for it.
    async fn incoming(&self, addr: String, ws_stream: impl WebSock) -> Result<(), Error> {
        // Create peer & websocket service task
        let (mut peer, ws_task) = self.create_peer(addr, ws_stream, PeerType::Incoming);

        // Send handshake
        peer.send_msg(msg![0, "HELLO", Self::VERSION]).await?;

        // Send known announce hashes
        let hash_list = {
            let anns = self.anns.lock();
            anns.hash_list().clone()
        };
        for h in hash_list.chunks(128) {
            peer.send_msg(msg![0, "INV", 0 => hashes = h]).await?;
        }

        // Send/Receive messages until websocket is closed
        let res = ws_task.await;

        // Drop peer
        self.drop_peer(peer);

        res
    }

    /// Handle outgoing WebSocket connection and process it until closed.
    /// This async fn completes when the connection is closed, so spawn a task for it.
    async fn outgoing(&self, addr: String, ws_stream: impl WebSock) -> Result<(), Error> {
        // Create peer & websocket service task
        let (mut peer, ws_task) = self.create_peer(addr, ws_stream, PeerType::Outgoing);

        // Send handshake
        peer.send_msg(msg![0, "OLLEH", Self::VERSION]).await?;

        // Send/Receive messages until websocket is closed
        let res = ws_task.await;

        // Drop peer
        self.drop_peer(peer);

        res
    }

    fn create_peer<'a>(&'a self, addr: String, ws_stream: impl WebSock + 'a, peer_type: PeerType) -> (Peer, impl Future<Output = Result<(), Error>> + 'a) {
        // Create bounded channel to send messages
        const QUEUE_SIZE: usize = 1024;
        let (msg_tx, msg_rx) = mpsc::channel(QUEUE_SIZE);

        // Clone announcement tx channel
        let ann_tx = self.announce_tx.clone();

        // Create peer struct
        let peer = self.peers.create_peer(peer_type, addr, msg_tx);

        // Create the websocket servicing task
        let ws_task = self.run_websocket(peer.clone(), ws_stream, msg_rx, ann_tx);

        (peer, ws_task)
    }

    fn drop_peer(&self, peer: Peer) {
        self.peers.remove_peer(peer.id);
    }

    async fn run_websocket(
        &self,
        peer: Peer,
        ws_stream: impl WebSock,
        mut msg_rx: mpsc::Receiver<Message>,
        mut ann_tx: mpsc::Sender<AnnData>,
    ) -> Result<(), Error> {
        // Split the socket
        let (mut ws_write, mut ws_read) = ws_stream.ws_split();

        // Socket handling loop
        loop {
            select! {
                Some(msg) = msg_rx.recv() => {
                    let ws_message = msg.encode_msgpack()?;
                    ws_write.send(ws_message).await?;
                    //ws_write.flush().await?;
                }
                Some(ws_message) = ws_read.next() => {
                    let bytes = ws_message?;
                    let message = Message::decode_msgpack(&bytes)?;
                    self.handle_message(peer.clone(), message, &mut ann_tx).await?;
                }
                else => break,
            }
        }

        Ok(())
    }

    async fn handle_message(&self, mut peer: Peer, message: Message, ann_tx: &mut mpsc::Sender<AnnData>) -> Result<(), Error> {
        let Message(id, msg) = message;

        *peer.last_msg_time.write() = Instant::now();

        use MessageData::*;

        // Validate message
        match &msg {
            msg @ HELLO(_) | msg @ OLLEH(_) => {
                let is_outgoing_peer = peer.peer_type == PeerType::Outgoing;
                let is_outgoing_hello = matches!(*msg, HELLO(_));
                if is_outgoing_hello != is_outgoing_peer {
                    let (peer_id, peer_addr) = (peer.id, peer.addr.clone());
                    self.drop_peer(peer);
                    return Err(anyhow!("Bad hello message from peer {} ip {}", peer_id, peer_addr));
                }
            }
            _ => {}
        }

        // Process message
        match msg {
            HELLO(version) | OLLEH(version) => {
                info!("Connected to snode with version [{}]", version);
            }

            GET_DATA(hash) => {
                // Lookup announce by hash, use empty vec if not found (should not normally happen)
                let ann = {
                    let anns = self.anns.lock();
                    anns.get(&hash).unwrap_or_default()
                };
                peer.send_msg(Message(id, MessageData::DATA(ann))).await?;
                //TODO Ask CJ whether it is possible to have empty announce data and under what circumstances
            }

            PING => {
                info!(">PING");
                peer.send_msg(msg![id, "ACK"]).await?;
            }

            ACK => { /* no-op */ }

            INV(hash_list) => {
                if peer.peer_type == PeerType::Outgoing {
                    for hash in hash_list {
                        if !self.anns.lock().hash_known(&hash) {
                            let seq = self.msg_id_seq.next();
                            peer.add_pending_req(seq);
                            peer.send_msg(msg![seq, "GET_DATA" | hash = hash]).await?;
                        }
                    }
                }
            }

            DATA(data) => {
                if peer.peer_type == PeerType::Outgoing {
                    let known_id = peer.complete_req(id);
                    if !known_id {
                        return Err(anyhow!("Unexpected DATA received, id={}", id));
                    }
                    ann_tx.send(data).await?;
                } else {
                    warn!("Data from an incoming connection");
                }
            }
        }

        Ok(())
    }
}
