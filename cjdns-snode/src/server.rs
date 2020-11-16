//! CJDNS supernode implementation.

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

use cjdns_ann::{AnnHash, Announcement, AnnouncementPacket, Entity, LINK_STATE_SLOTS};
use cjdns_keys::CJDNS_IP6;

use crate::config::Config;
use crate::peer::{AnnData, create_peers, Peers};
use crate::server::link::{Link, LinkStateEntry, mk_link};
use crate::server::nodes::{Node, Nodes};
use crate::server::route::Routing;
use crate::utils::task::periodic_task;
use crate::utils::timestamp::{mktime, time_diff};

mod hash;
mod link;
mod nodes;
mod route;
mod service;
mod utils;
mod webserver;
pub mod websock;

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
        let server = Arc::clone(&server);
        let h = task::spawn(service::service_task(server));
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

    // Await all spawned tasks
    try_join_all(tasks).await.map(|_| ()).map_err(|e| e.into())
}

fn print_entity(e: &cjdns_ann::Entity) -> String {
    match e {
        cjdns_ann::Entity::Peer(p) => format!("{}/{}", p.ipv6, p.peer_num),
        _ => format!("{:?}", e),
    }
}
fn print_entities(it: Vec<&cjdns_ann::Entity>) -> String {
    it.iter().map(|e| print_entity(&e)).collect::<Vec<String>>().join(", ")
}

struct Server {
    peers: Arc<Peers>,
    nodes: Nodes,
    mut_state: Mutex<ServerMut>,
}

struct ServerMut {
    debug_node: Option<CJDNS_IP6>, //TODO Debugging feature - need to implement log filtering
    self_node: Option<Arc<Node>>,
    current_node: Option<CJDNS_IP6>,
    routing: Routing,
}

#[derive(Debug)]
enum ReplyError {
    None,
    FailedParseOrValidate,
    OldMessage,
    WrongSnode,
    ExcessiveClockSkew,
    NoEncodingScheme,
    NoVersion,
    UnknownNode,
}

impl Server {
    fn new(peers: Arc<Peers>) -> Self {
        Server {
            peers: peers.clone(),
            nodes: Nodes::new(peers),
            mut_state: Mutex::new(ServerMut {
                debug_node: None,
                self_node: None,
                current_node: None,
                routing: Routing::new(),
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
        let res = self.handle_announce_impl(announce, from_node, None).await;
        if let Err(err) = res {
            warn!("Bad announcement: {}", err);
        }
    }

    async fn handle_announce_impl(&self, announce: Vec<u8>, from_node: bool, maybe_debug_noisy: Option<bool>) -> Result<(AnnHash, ReplyError), Error> {
        let mut reply_error = ReplyError::None;

        let mut ann_opt = None;
        let mut self_node = None;
        let mut node = None;
        let mut debug_noisy = if let Some(dn) = maybe_debug_noisy { dn } else { false };

        if let Ok(announcement_packet) = AnnouncementPacket::try_new(announce) {
            if announcement_packet.check().is_ok() {
                ann_opt = announcement_packet.parse().ok();
            }
        }
        if ann_opt.is_none() {
            reply_error = ReplyError::FailedParseOrValidate;
        }

        if let Some(ann) = ann_opt.as_ref() {
            self_node = {
                let mut state = self.mut_state.lock();
                state.current_node = Some(ann.node_ip.clone());
                if maybe_debug_noisy.is_none() {
                    debug_noisy = if let Some(dn) = &state.debug_node { dn.eq(&ann.node_ip) } else { false };
                }
                state.self_node.as_ref().map(|n| n.clone())
            };
            node = self.nodes.by_ip(&ann.node_ip);
            if log_enabled!(log::Level::Debug) && debug_noisy {
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

        if from_node {
            let self_node = self_node.ok_or_else(|| anyhow!("no self_node"))?;
            if let Some(ann) = ann_opt.as_ref() {
                if ann.node_ip != self_node.ipv6 {
                    warn!("announcement meant for other snode");
                    reply_error = ReplyError::WrongSnode;
                    ann_opt = None;
                }
            }
            if let Some(ann) = ann_opt.as_ref() {
                let clock_skew = time_diff(SystemTime::now(), mktime(ann.header.timestamp));
                if clock_skew > MAX_CLOCKSKEW {
                    warn!("unacceptably large clock skew {}h", clock_skew.as_secs_f64() / 60.0 / 60.0);
                    reply_error = ReplyError::ExcessiveClockSkew;
                    ann_opt = None;
                } else {
                    trace!("clock skew {}ms", clock_skew.as_millis());
                }
            }
        } else {
            if let (Some(self_node), Some(ann)) = (self_node, ann_opt.as_ref()) {
                if ann.node_ip == self_node.ipv6 {
                    warn!("announcement received by gossip which is meant for us");
                    reply_error = ReplyError::WrongSnode;
                    ann_opt = None;
                }
            }
        }

        let scheme = {
            if let Some(s) = ann_opt.as_ref().map(utils::encoding_scheme_from_announcement) {
                s.cloned().map(Arc::new)
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
                return Ok((hash::node_announcement_hash(node, debug_noisy), reply_error));
            }
        };
        let ann_timestamp = mktime(ann.header.timestamp);

        if let Some(node) = node.as_ref() {
            let node_timestamp = node.mut_state.read().timestamp;
            if node_timestamp > ann_timestamp { //TODO suspicious - duplicate check? Ask CJ
                warn!("old announcement [{}] most recent [{:?}]", ann.header.timestamp, node_timestamp);
                return Ok((hash::node_announcement_hash(Some(node.clone()), debug_noisy), reply_error));
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
            self.add_announcement(node.clone(), &ann, debug_noisy);
        } else {
            warn!("no node and no reset message");
            reply_error = ReplyError::UnknownNode;
            return Ok((hash::node_announcement_hash(None, debug_noisy), reply_error));
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
                        let mut stored_link_state = stored_link.mut_state.lock();
                        let new_link_state = new_link.mut_state.lock();
                        stored_link_state.flags = new_link_state.flags;
                        stored_link_state.mtu = new_link_state.mtu;
                        stored_link_state.time = new_link_state.time;
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

        self.link_state_update1(&ann, node.clone(), debug_noisy);

        let has_ann = {
            let node_mut = node.mut_state.read();
            node_mut.announcements.iter().any(|a| *a == ann) || node_mut.reset_msg.as_ref().map(|reset_msg| *reset_msg == ann).unwrap_or(false)
        };
        if has_ann {
            self.peers.add_ann(ann.hash.clone(), ann.binary.clone()).await;
        }

        return Ok((hash::node_announcement_hash(Some(node), debug_noisy), reply_error));
    }

    fn add_announcement(&self, node: Arc<Node>, ann: &Announcement, debug_noisy: bool) {
        let time = mktime(ann.header.timestamp);
        let since_time = time - AGREED_TIMEOUT;
        let mut drop_announce = Vec::new();
        let mut entities_announced = Vec::new();
        let mut node_mut = node.mut_state.write();
        node_mut.announcements.insert(0, ann.clone()); //TODO ask CJ whether the order of the announces matters
        node_mut.announcements.retain(|a| {
            if mktime(a.header.timestamp) < since_time {
                if debug_noisy {
                    debug!("Expiring ann [{}] because it is too old", utils::ann_id(a));
                }
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
                    if debug_noisy {
                        debug!("Keeping ann [{}] because it was announced just now", utils::ann_id(a));
                    }
                } else {
                    if debug_noisy {
                        debug!("Keeping ann [{}] for entities [{}]", utils::ann_id(a), print_entities(justifications));
                    }
                }
                return true;
            } else {
                if debug_noisy {
                    debug!(
                        "Dropping ann [{}] because all entities [{}] have been re-announced",
                        utils::ann_id(a),
                        print_entities(justifications)
                    );
                }
                drop_announce.push(a.clone());
                return false;
            }
        });

        if debug_noisy {
            debug!("Finally there are {} anns in the state", node_mut.announcements.len());
        }
        for a in drop_announce {
            if node_mut.reset_msg.as_ref().map(|reset_msg| a != *reset_msg).unwrap_or(true) {
                self.peers.del_ann(&a.hash);
            }
        }
        node_mut.timestamp = time;
    }

    fn link_state_update1(&self, ann: &Announcement, node: Arc<Node>, debug_noisy: bool) {
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

                {
                    let mut link_mut = link.mut_state.lock();
                    if link_mut.most_recent_ls_slot > ts {
                        let decay_slots = link_mut.most_recent_ls_slot - ts;
                        link_mut.value /= 1.0 + (decay_slots as f64 * Link::DECAY_PER_TIMESLOT);
                    }
                    link_mut.most_recent_ls_slot = ts;
                }

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
                        let lsv = new_state.ls_value();
                        assert!(lsv >= 0.0, "lsv {} for ls {:?}", lsv, new_state);
                        let delta_v = lsv / (1.0 + (ts - time) as f64 * Link::DECAY_PER_TIMESLOT);
                        assert!(delta_v >= 0.0);
                        link.mut_state.lock().value += delta_v;
                        if debug_noisy {
                            debug!("LSU {} <- {}/{} : {:?}", ann.node_ip, ips_by_num[&ls.node_id], ls.node_id, new_state);
                        }
                        link_state.insert(time, new_state);
                        time -= 1;
                    }

                    index -= 1;
                }
            }
        }
    }
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ReplyError::None => write!(f, "none"),
            ReplyError::FailedParseOrValidate => write!(f, "failed_parse_or_validate"),
            ReplyError::OldMessage => write!(f, "old_message"),
            ReplyError::WrongSnode => write!(f, "wrong_snode"),
            ReplyError::ExcessiveClockSkew => write!(f, "excessive_clock_skew"),
            ReplyError::NoEncodingScheme => write!(f, "no_encodingScheme"),
            ReplyError::NoVersion => write!(f, "no_version"),
            ReplyError::UnknownNode => write!(f, "unknown_node"),
        }
    }
}