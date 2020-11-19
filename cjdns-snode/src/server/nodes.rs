//! IP to node mapping

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Error;
use parking_lot::{Mutex, RwLock};

use cjdns_ann::{AnnHash, Announcement};
use cjdns_bytes::Writer;
use cjdns_core::EncodingScheme;
use cjdns_keys::{CJDNSPublicKey, CJDNS_IP6};

use crate::peer::Peers;
use crate::server::link::Link;

pub(super) struct Nodes {
    peers: Arc<Peers>,
    /// Shared state guarded by a regular sync mutex (since we don't need to keep the lock between `.await` points)
    nodes_by_ip: RwLock<HashMap<CJDNS_IP6, Arc<Node>>>,
}

pub(super) struct Node {
    pub(super) node_type: NodeType,
    pub(super) version: u16,
    pub(super) key: CJDNSPublicKey,
    pub(super) ipv6: CJDNS_IP6,
    pub(super) encoding_scheme: Arc<EncodingScheme>,
    pub(super) inward_links_by_ip: Mutex<HashMap<CJDNS_IP6, Vec<Link>>>,
    pub(super) mut_state: RwLock<NodeMut>,
}

pub(super) struct NodeMut {
    pub(super) timestamp: SystemTime,
    pub(super) announcements: Vec<Announcement>,
    pub(super) state_hash: Option<AnnHash>,

    // Dirty trick to preserve the last reset message in order to
    // allow downstream snode peers to be able to get the version and the
    // encoding scheme of the node without telling the node that in fact we
    // have to preserve this stuff, because it thinks we're going to delete them
    // and if we don't tell it the right hash, it will go into desync mode.
    pub(super) reset_msg: Option<Announcement>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum NodeType {
    Node,
}

// No async methods allowed here since we use sync mutex
impl Nodes {
    pub fn new(peers: Arc<Peers>) -> Self {
        Nodes {
            peers,
            nodes_by_ip: RwLock::new(HashMap::new()),
        }
    }

    pub fn all_ips(&self) -> Vec<CJDNS_IP6> {
        // Cloning all the IP6's can be costy.
        // Alternative approcah is to lock the original hashmap during the graph rebuild, but isn't it too long?
        self.nodes_by_ip.read().keys().cloned().collect()
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
        encoding_scheme: Option<Arc<EncodingScheme>>,
        timestamp: SystemTime,
        ipv6: CJDNS_IP6,
        announcement: Option<Announcement>,
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
            reset_msg: None,
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

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.node_type == other.node_type
            && self.version == other.version
            && self.key == other.key
            && self.ipv6 == other.ipv6
            && *self.encoding_scheme == *other.encoding_scheme
    }
}

impl Eq for Node {}
