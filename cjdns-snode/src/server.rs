//! CJDNS supernode implementation.

#![allow(unused_variables)] //TODO Remove when done
#![allow(unused_assignments)] //TODO Remove when done

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Error;
use anyhow::Result;
use futures::future::try_join_all;
use futures::StreamExt;
use http::Uri;
use parking_lot::Mutex;
use tokio::task;
use sodiumoxide::crypto::hash::sha512;

use cjdns_ann::{Announcement, AnnouncementPacket, Entity, LINK_STATE_SLOTS};
use cjdns_keys::CJDNS_IP6;

use crate::config::Config;
use crate::peer::{AnnData, create_peers, Peers};
use crate::server::link::{Link, LinkStateEntry, mk_link};
use crate::server::nodes::{Node, Nodes};
use crate::utils::task::periodic_task;
use crate::utils::timestamp::{mktime, time_diff};

const KEEP_TABLE_CLEAN_CYCLE: Duration = Duration::from_secs(30);

/// Server entry point. Requires config (loaded from an external file) to run.
pub async fn main(config: Config) -> Result<()> {
    // Background tasks we are going to spawn
    let mut tasks = Vec::new();

    // The server context instance
    let (peers, announces) = create_peers();
    let peers = Arc::new(peers);
    let server = Arc::new(Server::new(Arc::clone(&peers)));

    // Run timeout task
    {
        let server = Arc::clone(&server);
        let h = task::spawn(periodic_task(KEEP_TABLE_CLEAN_CYCLE, move || server.nodes.keep_table_clean()));
        tasks.push(h);
    }

    // Run peer pings task
    {
        let peers = Arc::clone(&peers);
        let h = task::spawn(async move { peers.ping_task().await });
        tasks.push(h);
    }

    // Run announcements handling task
    {
        let server = Arc::clone(&server);
        let h = task::spawn(async move { announces.for_each(|ann| { server.handle_announce(ann, false) }).await; });
        tasks.push(h);
    }

    // Connect to local CJDNS router, if configured
    if config.connect {
        let h = task::spawn(service::service_task());
        tasks.push(h);
    }

    // Start supernode HTTP/WebSocket server task
    {
        let server = Arc::clone(&server);
        let h = task::spawn(webserver::test_srv_task(server));
        tasks.push(h);
    }

    // Connect to peer supernodes
    for peer_addr in config.peers.iter() {
        match Uri::from_str(peer_addr) {
            Ok(uri) => {
                let peers = Arc::clone(&peers);
                let h = task::spawn(async move { peers.connect_to(uri).await });
                tasks.push(h);
            },
            Err(err) => {
                error!("Unable to connect to {}: {}", peer_addr, err);
            }
        }
    }

    // Disconnect all peers on interrupt
    //TODO call this only on interrupt
    peers.disconnect_all().await;

    // Await all spawned tasks
    try_join_all(tasks).await.map(|_| ()).map_err(|e| e.into())
}

struct Server {
    peers: Arc<Peers>,
    nodes: Nodes,
    mut_state: Mutex<ServerMut>,
}

struct ServerMut {
    debug_node: Option<CJDNS_IP6>, //TODO Debugging feature - need to implement log filtering
    //last_rebuild: Instant, //TODO Milestone 3
    self_node: Option<Arc<Node>>,
    //route_cache: (), //TODO Milestone 3
    current_node: Option<CJDNS_IP6>,
}

#[derive(Debug)]
enum ReplyError {
    FailedParseOrValidate,
    OldMessage,
    WrongSnode,
    ExcessiveClockSkew,
    NoEncodingScheme,
    NoVersion,
    UnknownNode,
    None
}

impl Server {
    //const VERSION: u32 = 1; //TODO Milestone 3

    fn new(peers: Arc<Peers>) -> Self {
        Server {
            peers: peers.clone(),
            nodes: Nodes::new(peers),
            mut_state: Mutex::new(ServerMut {
                debug_node: None,
                //last_rebuild: Instant::now(),
                self_node: None,
                //route_cache: (),
                current_node: None,
            }),
        }
    }
}

const MINUTE: u64 = 60;
const AGREED_TIMEOUT: Duration = Duration::from_secs(20 * MINUTE);
const MAX_CLOCKSKEW: Duration = Duration::from_secs(10);
const MAX_GLOBAL_CLOCKSKEW: Duration = Duration::from_secs(60 * 60 * 20);
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(MAX_GLOBAL_CLOCKSKEW.as_secs() + AGREED_TIMEOUT.as_secs());

impl Server {
    async fn handle_announce(&self, announce: AnnData, from_node: bool) {
        let res = self.handle_announce_impl(announce, from_node).await;
        if let Err(err) = res {
            warn!("Bad announcement: {}", err);
        }
    }

    async fn handle_announce_impl(&self, announce: Vec<u8>, from_node: bool) -> Result<(sha512::Digest, ReplyError), Error> {
        let mut reply_error = ReplyError::None;

        let mut ann_opt = {
            let mut ret = None;
            if let Some(announcement_packet) = AnnouncementPacket::try_new(announce).ok() {
                if announcement_packet.check().is_ok() {
                    ret = announcement_packet.parse().ok();
                }
            }
            ret
        };
        if ann_opt.is_none() {
            reply_error = ReplyError::FailedParseOrValidate;
        }

        let mut self_node = None;
        let mut node = None;

        if let Some(ann) = ann_opt.as_ref() {
            self_node = {
                let mut state = self.mut_state.lock();
                state.current_node = Some(ann.node_ip.clone());
                state.self_node.as_ref().map(|n| n.clone())
            };
            node = self.nodes.by_ip(&ann.node_ip);
            if log_enabled!(log::Level::Debug) {
                debug!(
                    "ANN from [{}] ts [{}] isReset [{}] peers [{}] ls [{}] known [{}]{}",
                    ann.node_ip,
                    ann.header.timestamp,
                    ann.header.is_reset,
                    ann.entities.iter().filter(|&a| matches!(&a, Entity::Peer{..})).count(),
                    ann.entities.iter().filter(|&a| matches!(&a, Entity::LinkState{..})).count(),
                    node.is_some(),
                    if node.is_none() && !ann.header.is_reset { " ERR_UNKNOWN" } else { "" }
                );
            }
        }

        if let (Some(node), Some(ann)) = (node.as_ref(), ann_opt.as_ref()) {
            let node_mut = node.mut_state.read();
            let ann_timestamp = mktime(ann.header.timestamp);
            if from_node && node_mut.timestamp > ann_timestamp {
                warn!("old timestamp");
                reply_error = ReplyError::OldMessage;
                ann_opt = None;
            }
        }

        let max_clock_skew = {
            if from_node {
                let self_node = self_node.ok_or_else(|| anyhow!("no self_node"))?;
                if let Some(ann) = ann_opt.as_ref() {
                    if ann.node_ip != self_node.ipv6 {
                        warn!("announcement from peer which is one of ours");
                        reply_error = ReplyError::WrongSnode;
                        ann_opt = None;
                    }
                }
                MAX_CLOCKSKEW
            } else {
                if let (Some(self_node), Some(ann)) = (self_node, ann_opt.as_ref()) {
                    if ann.node_ip == self_node.ipv6 {
                        warn!("announcement meant for other snode");
                        reply_error = ReplyError::WrongSnode;
                        ann_opt = None;
                    }
                }
                MAX_GLOBAL_CLOCKSKEW
            }
        };

        if let Some(ann) = ann_opt.as_ref() {
            let clock_skew = time_diff(SystemTime::now(), mktime(ann.header.timestamp));
            if clock_skew > max_clock_skew {
                warn!("unacceptably large clock skew {}h", clock_skew.as_secs_f64() / 60.0 / 60.0);
                reply_error = ReplyError::ExcessiveClockSkew;
                ann_opt = None;
            } else {
                trace!("clock skew {}ms", clock_skew.as_millis());
            }
        }

        let scheme = {
            if let Some(s) = ann_opt.as_ref().map(utils::encoding_scheme_from_announcement) {
                s.cloned()
            } else if let Some(node) = node.as_ref() {
                Some(node.encoding_scheme.clone())
            } else if ann_opt.is_some() {
                warn!("no encoding scheme");
                reply_error = ReplyError::NoEncodingScheme;
                ann_opt = None;
                None
            } else {
                None
            }
        };

        let version = {
            if let Some(ver) = ann_opt.as_ref().map(utils::version_from_announcement) {
                ver
            } else if let Some(node) = node.as_ref() {
                Some(node.version)
            } else if ann_opt.is_some() {
                warn!("no version");
                reply_error = ReplyError::NoVersion;
                ann_opt = None;
                None
            } else {
                None
            }
        };

        let ann = {
            if let Some(ann) = ann_opt {
                ann
            } else {
                return Ok((self.node_announcement_hash(node), reply_error));
            }
        };
        let ann_timestamp = mktime(ann.header.timestamp);

        if let Some(node) = node.as_ref() {
            // we do not return state hash after call to `warn!()`, because hash computation requires write lock,
            // but read lock is already acquired
            let is_old_ann = {
                let node_mut = node.mut_state.read();
                let is_old_ann = node_mut.timestamp > ann_timestamp;
                if is_old_ann { warn!("old announcement [{}] most recent [{:?}]", ann.header.timestamp, node_mut.timestamp); } //TODO suspicious - duplicate check? Ask CJ
                is_old_ann
            };
            if is_old_ann {
                return Ok((self.node_announcement_hash(Some(node.clone())), reply_error));
            }
        }

        if ann.header.is_reset {
            let n = self.nodes.new_node(
                version.unwrap(),
                ann.node_pub_key.clone(),
                scheme,
                ann_timestamp,
                ann.node_ip.clone(),
                Some(ann.clone()),
            )?;
            let try_node = self.nodes.add_node(n, true);
            node = Some(try_node.map_err(|()| anyhow!("internal error: add_node() failed"))?);
        } else if let Some(node) = node.as_ref() {
            self.add_announcement(node.clone(), &ann);
        } else {
            warn!("no node and no reset message");
            reply_error = ReplyError::UnknownNode;
            return Ok((self.node_announcement_hash(None), reply_error));
        }

        let node = node.expect("internal error: node expected"); // Due to the above checks it should be valid node here

        'peer: for peer in utils::peers_from_announcement(&ann) {
            let mut inward_links_by_ip = node.inward_links_by_ip.lock();

            if peer.label.is_none() {
                if let Some(links) = inward_links_by_ip.get_mut(&peer.ipv6) {
                    links.retain(|l| l.peer_num != peer.peer_num);
                    if links.is_empty() {
                        inward_links_by_ip.remove(&peer.ipv6);
                    }
                } else {
                    // Withdrawal of a route we never heard of - do nothing
                }
                continue 'peer;
            }

            let stored = inward_links_by_ip.get_mut(&peer.ipv6);
            let new_link = mk_link(peer, &ann);

            if let Some(stored) = stored {
                'link: for stored_link in stored.iter_mut() {
                    if stored_link.peer_num != new_link.peer_num {
                        continue 'link;
                    }
                    if stored_link.label != new_link.label {
                        // nothing
                    } else if stored_link.encoding_form_number != new_link.encoding_form_number {
                        // nothing
                    } else {
                        // only small changes (if any)
                        stored_link.flags = new_link.flags;
                        stored_link.mtu = new_link.mtu;
                        stored_link.time = new_link.time;
                        continue 'peer;
                    }
                    // major changes, replace the link and wipe out link state
                    *stored_link = new_link;
                    continue 'peer;
                }
                // We get here when there is no match
                stored.push(new_link);
            } else {
                inward_links_by_ip.insert(peer.ipv6.clone(), vec![new_link]);
                continue 'peer;
            }
        }

        self.link_state_update1(&ann, node.clone());

        let has_ann = {
            let node_mut = node.mut_state.read();
            node_mut.announcements.iter().any(|a| *a == ann) || node_mut.reset_msg.as_ref().map(|reset_msg| *reset_msg == ann).unwrap_or(false)
        };
        if has_ann {
            self.peers.add_ann(ann.hash.clone(), ann.binary.clone()).await;
        }

        return Ok((self.node_announcement_hash(Some(node)), reply_error));
    }

    fn add_announcement(&self, node: Arc<Node>, ann: &Announcement) {
        let time = mktime(ann.header.timestamp);
        let since_time = time - AGREED_TIMEOUT;
        let mut drop_announce = Vec::new();
        let mut entities_announced = Vec::new();
        let mut node_mut = node.mut_state.write();
        node_mut.announcements.insert(0, ann.clone()); //TODO ask CJ whether the order of the announces matters
        node_mut.announcements.retain(|a| {
            if mktime(a.header.timestamp) < since_time {
                debug!("Expiring ann [{}] because it is too old", utils::ann_id(a));
                drop_announce.push(a.clone());
                return false;
            }

            let mut safe = false;
            let mut justifications = Vec::new();
            for e in a.entities.iter() {
                if utils::is_entity_ephemeral(e) {
                    continue;
                }

                if entities_announced.iter().filter(|&je| utils::is_entity_replacement(e, je)).count() == 0 {
                    safe = true;
                    justifications.push(e);
                    entities_announced.push(e.clone());
                }
            }

            // current announcement is always safe because it might not have actually announced anything
            // in which case it's an empty announce just to let the snode know the node is still here...
            if safe || *a == *ann {
                if *a == *ann {
                    debug!("Keeping ann [{}] because it was announced just now", utils::ann_id(a));
                } else {
                    debug!("Keeping ann [{}] for entities [{:?}]", utils::ann_id(a), justifications);
                }
                return true;
            } else {
                debug!("Dropping ann [{}] because all entities [{:?}] have been re-announced", utils::ann_id(a), justifications);
                drop_announce.push(a.clone());
                return false;
            }
        });

        debug!("Finally there are {} anns in the state", node_mut.announcements.len());
        for a in drop_announce {
            if node_mut.reset_msg.as_ref().map(|reset_msg| a != *reset_msg).unwrap_or(true) {
                self.peers.del_ann(&a.hash);
            }
        }
        node_mut.timestamp = time;
    }

    fn link_state_update1(&self, ann: &Announcement, node: Arc<Node>) {
        let time = ann.header.timestamp;
        let ts = time / 1000 / 10;
        // Timeslots older than AGREED_TIMEOUT will be dropped
        let earliest_ok_ts = ts - (AGREED_TIMEOUT.as_millis() as u64 / 1000 / 10);

        let mut inward_links_by_num = HashMap::<u16, Link>::new();
        let mut ips_by_num = HashMap::<u16, CJDNS_IP6>::new();

        for (peer_ip, peers) in node.inward_links_by_ip.lock().iter() {
            for peer in peers {
                inward_links_by_num.insert(peer.peer_num, peer.clone());
                ips_by_num.insert(peer.peer_num, peer_ip.clone());
            }
        }

        for ls in utils::link_states_from_announcement(ann) {
            if let Some(link) = inward_links_by_num.get(&ls.node_id) {
                let mut link_state = link.link_state.lock();

                link_state.retain(|&old_ls, _| {
                    let drop = old_ls < earliest_ok_ts;
                    //if drop {
                    //    warn!("dropping link state slot {} from {} for age", old_ls, ann.node_ip);
                    //}
                    !drop
                });

                // The `starting_point` is the index of the *oldest* entry, newer entries continue forward from
                // this entry. To save space, cjdns doesn't send any more entries than it needs to, which
                // means while deserializing, the nonexistant entries will be filled by `None`s.
                //
                // We will assign the newest entry the timeslot corresponding to the time of the announcement
                // itself, but we don't know the timestamp of the starting point. To solve this, we
                // walk backward from the starting point, looping at the end. But since the array is filled
                // with empty space (`None`s), we need to be careful not to start deincrementing the timeslot
                // until we hit actual numbers.

                let sp = (ls.starting_point % LINK_STATE_SLOTS) as i8;
                let mut time = ts;
                let mut index = sp - 1;
                while index != sp {
                    if index < 0 {
                        index = (LINK_STATE_SLOTS - 1) as i8;
                        continue;
                    }

                    let i = index as usize;

                    // If there's already a time entry for this slot, we don't care because new data wins.
                    //if link_state.contains_key(&ts) { continue; } // TODO: check if the numbers are the same?

                    if let (Some(drop_slot), Some(lag_slot), Some(kb_recv_slot)) = (ls.drop_slots[i], ls.lag_slots[i], ls.kb_recv_slots[i]) {
                        let new_state = LinkStateEntry {
                            drops: drop_slot,
                            lag: lag_slot,
                            kb_recv: kb_recv_slot,
                        };
                        debug!(
                            "LINK_STATE_UPDATE: time={}, node_ip={}, ips_by_num[{}]={}, label={}, new_state={:?}",
                            time, ann.node_ip, ls.node_id, ips_by_num[&ls.node_id], link.label, new_state
                        );
                        link_state.insert(time, new_state);
                        time -= 1;
                    }

                    index -= 1;
                }
            }
        }
    }

    fn node_announcement_hash(&self, node: Option<Arc<Node>>) -> sha512::Digest {
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
            node_mut.state_hash = Some(carry);
        }
        debug!("node announcement hash - {}, state - {}", hex::encode(carry), state);
        carry
    }
}

mod nodes {
    //! IP to node mapping

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::SystemTime;

    use anyhow::Error;
    use parking_lot::{Mutex, RwLock};
    use sodiumoxide::crypto::hash::sha512;

    use cjdns_ann::Announcement;
    use cjdns_core::EncodingScheme;
    use cjdns_keys::{CJDNS_IP6, CJDNSPublicKey};
    use cjdns_bytes::Writer;

    use crate::peer::Peers;
    use crate::server::link::Link;

    pub(super) struct Nodes {
        peers: Arc<Peers>,
        /// Shared state guarded by a regular sync mutex (since we don't need to keep the lock between `.await` points)
        nodes_by_ip: RwLock<HashMap<CJDNS_IP6, Arc<Node>>>
    }

    pub(super) struct Node {
        pub(super) node_type: NodeType,
        pub(super) version: u16,
        #[allow(dead_code)] //TODO Milestone 3
        pub(super) key: CJDNSPublicKey,
        pub(super) ipv6: CJDNS_IP6,
        pub(super) encoding_scheme: EncodingScheme,
        pub(super) inward_links_by_ip: Mutex<HashMap<CJDNS_IP6, Vec<Link>>>,
        pub(super) mut_state: RwLock<NodeMut>,
    }

    pub(super) struct NodeMut {
        pub(super) timestamp: SystemTime,
        pub(super) announcements: Vec<Announcement>,
        pub(super) state_hash: Option<sha512::Digest>,

        // Dirty trick to preserve the last reset message in order to
        // allow downstream snode peers to be able to get the version and the
        // encoding scheme of the node without telling the node that in fact we
        // have to preserve this stuff, because it thinks we're going to delete them
        // and if we don't tell it the right hash, it will go into desync mode.
        pub(super) reset_msg: Option<Announcement>,
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub(super) enum NodeType { Node }

    // No async methods allowed here since we use sync mutex
    impl Nodes {
        pub fn new(peers: Arc<Peers>) -> Self {
            Nodes {
                peers,
                nodes_by_ip: RwLock::new(HashMap::new()),
            }
        }

        pub fn by_ip(&self, ip: &CJDNS_IP6) -> Option<Arc<Node>> {
            self.nodes_by_ip.read().get(ip).cloned()
        }

        pub fn count(&self) -> usize {
            self.nodes_by_ip.read().len()
        }

        pub fn anns_dump(&self) -> Vec<u8> {
            let mut writer = Writer::new();
            let nodes_by_ip = self.nodes_by_ip.read();
            for node in nodes_by_ip.values() {
                let state = node.mut_state.read();
                for ann in &state.announcements {
                    writer.write_u32_be(ann.binary.len() as u32);
                    writer.write_slice(&ann.binary);
                }
            }
            writer.write_u32_be(0);
            writer.into_vec()
        }

        pub fn keep_table_clean(&self) {
            trace!("keep_table_clean()");

            let min_time = SystemTime::now() - super::GLOBAL_TIMEOUT;

            let mut nodes_by_ip = self.nodes_by_ip.write();
            nodes_by_ip.retain(|_node_ip, node| {
                let node_mut = node.mut_state.read();
                if node_mut.timestamp < min_time {
                    warn!("forgetting node [{}]", node.ipv6);
                    self.forget_node(node.clone());
                    false // Remove node
                } else {
                    true // Keep this node
                }
            });
        }

        pub(super) fn new_node(
            &self,
            version: u16,
            key: CJDNSPublicKey,
            encoding_scheme: Option<EncodingScheme>,
            timestamp: SystemTime,
            ipv6: CJDNS_IP6,
            announcement: Option<Announcement>
        ) -> Result<Node, Error> {
            let encoding_scheme = {
                if let Some(encoding_scheme) = encoding_scheme {
                    encoding_scheme
                } else {
                    if let Some(onode) = self.nodes_by_ip.read().get(&ipv6) {
                        onode.encoding_scheme.clone()
                    } else {
                        return Err(anyhow!("cannot create node we do not know its encoding scheme"));
                    }
                }
            };

            let mut out = NodeMut {
                timestamp,
                announcements: Vec::new(),
                state_hash: None,
                reset_msg: None
            };

            if let Some(ann) = announcement {
                out.reset_msg = Some(ann.clone());
                out.announcements.push(ann);
            }

            let res = Node {
                node_type: NodeType::Node,
                version,
                key,
                ipv6,
                encoding_scheme,
                inward_links_by_ip: Mutex::new(HashMap::new()),
                mut_state: RwLock::new(out),
            };

            Ok(res)
        }

        pub(super) fn add_node(&self, node: Node, overwrite: bool) -> Result<Arc<Node>, ()> {
            if node.node_type != NodeType::Node {
                return Err(());
            }

            let mut nodes = self.nodes_by_ip.write();
            let old_node = nodes.get(&node.ipv6).cloned();

            if !overwrite && old_node.is_some() {
                return Err(());
            }

            if let Some(old_node) = old_node {
                self.forget_node(old_node);
            }

            let node = Arc::new(node);
            nodes.insert(node.ipv6.clone(), node.clone());

            Ok(node)
        }

        fn forget_node(&self, node: Arc<Node>) {
            let node_mut = node.mut_state.read();
            for ann in node_mut.announcements.iter() {
                self.peers.del_ann(&ann.hash);
            }
            if let Some(reset_msg) = node_mut.reset_msg.as_ref() {
                self.peers.del_ann(&reset_msg.hash);
            }
        }
    }
}

mod link {
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

        pub(super) mtu: u32,
        pub(super) flags: u8,
        pub(super) time: u64,
        //pub(super) cost: (), //TODO Milestone 3
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
            mtu: ann_peer.mtu,
            flags: ann_peer.flags,
            time: ann.header.timestamp,
            //cost: (),
        }
    }
}

mod service;
mod webserver;
mod utils;
pub mod websock;