//! Local node (router) service task

use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Error;
use tokio::select;

use cjdns_admin::msgs::Empty;
use cjdns_bencode::BValue;
use cjdns_hdr::RouteHeader;
use cjdns_keys::{CJDNS_IP6, CJDNSPublicKey};
use cjdns_sniff::{Content, ContentType, Message, ReceiveError, Sniffer};

use crate::server::route::get_route;
use crate::server::Server;
use crate::server::service::core_node_info::try_parse_encoding_scheme;
use crate::utils::node::parse_node_name;
use crate::utils::timestamp::{current_timestamp, mktime};

use self::core_node_info::CoreNodeInfoPayload;

pub(super) async fn service_task(server: Arc<Server>) {
    let res = do_service(server).await;
    if let Err(err) = res {
        error!("Failed to service local node: {}", err)
    }
}

async fn do_service(server: Arc<Server>) -> Result<(), Error> {
    let mut cjdns = cjdns_admin::connect(None).await?;

    // Querying local node info
    let node_info = cjdns.invoke::<_, CoreNodeInfoPayload>("Core_nodeInfo", Empty{}).await?;

    let (version, _, pub_key) = parse_node_name(&node_info.my_addr).map_err(|_| anyhow!("malformed node name string returned by Core_nodeInfo()"))?;
    let ipv6 = CJDNS_IP6::try_from(&pub_key).map_err(|e| anyhow!("bad node public key returned by Core_nodeInfo(): {}", e))?;
    let encoding_scheme = try_parse_encoding_scheme(node_info.encoding_scheme).map_err(|e| anyhow!("bad encoding scheme returned by Core_nodeInfo(): {}", e))?;

    let self_node = server.nodes.new_node(
        version,
        pub_key,
        Some(encoding_scheme),
        mktime(0xffffffffffffffff),
        ipv6,
        None,
    )?;
    server.mut_state.lock().self_node = Some(Arc::new(self_node));

    debug!("Got selfNode");

    // Starting to sniff traffic
    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

    // todo check connection impl after implementing new routes for test_srv

    // Handling subnode messages
    loop {
        select! {
            msg = sniffer.receive() => {
                match msg {
                    Ok(msg) => {
                        let ret_msg_opt = on_subnode_message(server.clone(), msg).await?;
                        if let Some(ret_msg) = ret_msg_opt {
                            sniffer.send(ret_msg, None).await?;
                        }
                    }

                    Err(err @ ReceiveError::SocketError(_)) => {
                        return Err(err.into());
                    }

                    Err(ReceiveError::ParseError(err, data)) => {
                        debug!("Bad message received:\n{}\n{}", hex::encode(data), anyhow!(err));
                    }
                }
            }
        }
    }
}

/// Handles a message from local node, and returns a response message that should be sent in return.
async fn on_subnode_message(server: Arc<Server>, msg: Message) -> Result<Option<Message>, Error> {
    let (route_header, content_type, content) = (msg.route_header, msg.content_type, msg.content);
    if let Content::Benc(content_benc) = content {
        let res_route_header = {
            let mut h = route_header.clone();
            h.switch_header.label_shift = 0;
            h
        };
        let res = on_subnode_message_impl(server, route_header, content_benc).await?
            .map(|res_benc| {
                Message {
                    route_header: res_route_header,
                    content_type,
                    content: Content::Benc(res_benc),
                    raw_bytes: None
                }
            })
        ;
        Ok(res)
    } else {
        Err(anyhow!("bad message content - bencode expected"))
    }
}

async fn on_subnode_message_impl(server: Arc<Server>, route_header: RouteHeader, content_benc: BValue) -> Result<Option<BValue>, Error> {
    let sq = content_benc.get_dict_value_str("sq").map_err(|_| anyhow!("bad message: 'sq' string entry expected in root dict"))?;

    let version = {
        if route_header.version > 0 {
            Some(route_header.version)
        } else if let Some(p) = content_benc.get_dict_value("p").ok().flatten() {
            let p = p.as_int().ok().filter(|&p| p > 0).map(|p| p as u32).ok_or(anyhow!("bad message: 'p' expected to be positive int"))?;
            Some(p)
        } else {
            None
        }
    };

    if version.is_none() || route_header.public_key.is_none() || route_header.ip6.is_none() {
        if let Some(ip) = route_header.ip6.as_ref() {
            warn!("message from {} with missing key or version: {:?} {:?}", ip, route_header, content_benc);
        }
        return Ok(None);
    }

    let txid = content_benc.get_dict_value("txid").ok().flatten();

    server.mut_state.lock().current_node = route_header.ip6.clone();

    let res = match sq.as_str() {
        "gr" => {
            if !content_benc.has_dict_entry("src") {
                warn!("missing src");
                return Ok(None);
            }
            if !content_benc.has_dict_entry("tar") {
                warn!("missing tar");
                return Ok(None);
            }

            let src = content_benc.get_dict_value_bytes("src").map_err(|_| anyhow!("bad message: 'src' bytes entry expected in root dict"))?;
            let tar = content_benc.get_dict_value_bytes("tar").map_err(|_| anyhow!("bad message: 'tar' bytes entry expected in root dict"))?;

            let src_ip = CJDNS_IP6::try_from(src.as_slice()).map_err(|e| anyhow!("bad 'src' address: {}", e))?;
            let tar_ip = CJDNS_IP6::try_from(tar.as_slice()).map_err(|e| anyhow!("bad 'tar' address: {}", e))?;

            let src = server.nodes.by_ip(&src_ip);
            let tar = server.nodes.by_ip(&tar_ip);

            let res = BValue::builder()
                .set_dict()
                .add_dict_entry_opt("txid", txid)
                .add_dict_entry("recvTime", |b| b.set_int(current_timestamp() as i64))
            ;

            let route = get_route(server.clone(), src.clone(), tar.clone());

            let res = if let (Ok(route), Some(tar)) = (route, tar) {
                res
                    // List of nodes (one entry - the destination).
                    // Each node represented as its public key + routing label.
                    .add_dict_entry("n", |b| {
                        let label_bits = route.label.bits().to_be_bytes();
                        let mut buf = Vec::with_capacity(CJDNSPublicKey::SIZE + route.label.size());
                        buf.extend_from_slice(&tar.key);
                        buf.extend_from_slice(&label_bits);
                        b.set_bytes(buf)
                    })
                    // List of nodes' protocol version (one entry - the destination).
                    // The first byte is the number of bytes taken by each version in the list (always 1 for now),
                    // followed by the versions themselves, encoded in big endian.
                    .add_dict_entry("np", |b| {
                        let mut buf = Vec::with_capacity(2);
                        buf.push(1); // Number of bytes taken by each version
                        buf.push(tar.version as u8); // Version as 1-byte integer
                        b.set_bytes(buf)
                    })
            } else {
                res
            };

            Some(res.build())
        }

        "ann" if content_benc.has_dict_entry("ann") => {
            let ann = content_benc.get_dict_value_bytes("ann").expect("benc 'ann' entry"); // Safe because of the check above

            let (state_hash, reply_err) = server.handle_announce_impl(ann, true).await?;
            if let Some(self_node) = server.mut_state.lock().self_node.as_ref() {
                debug!("reply: {:?}", hex::encode(state_hash.bytes()));

                let res = BValue::builder()
                    .set_dict()
                    .add_dict_entry_opt("txid", txid)
                    .add_dict_entry("p", |b| b.set_int(self_node.version as i64))
                    .add_dict_entry("recvTime", |b| b.set_int(current_timestamp() as i64))
                    .add_dict_entry("stateHash", |b| b.set_bytes(state_hash.into_inner()))
                    .add_dict_entry("error", |b| b.set_str(reply_err.to_string()))
                    .build()
                ;

                Some(res)
            } else {
                return Err(anyhow!("self node isn't set"));
            }
        }

        "pn" => {
            let mut res = BValue::builder()
                .set_dict()
                .add_dict_entry_opt("txid", txid)
                .add_dict_entry("recvTime", |b| b.set_int(current_timestamp() as i64))
                .add_dict_entry("stateHash", |b| b.set_bytes([0u8; 64].to_vec()))
            ;

            if let Some(ip6) = route_header.ip6.as_ref() {
                if let Some(node) = server.nodes.by_ip(ip6) {
                    if let Some(state_hash) = node.mut_state.read().state_hash.as_ref() {
                        res = res.add_dict_entry("stateHash", |b| b.set_bytes(state_hash.clone().into_inner()));
                    }
                }
            } else {
                return Err(anyhow!("no ip6 (ctrl message?)"));
            }

            Some(res.build())
        }

        _ => {
            warn!("contentBenc {:?}", content_benc);
            None
        }
    };

    server.mut_state.lock().current_node = None;

    Ok(res)
}

mod core_node_info {
    use std::convert::{TryFrom, TryInto};

    use anyhow::Error;
    use serde::Deserialize;

    use cjdns_core::{EncodingScheme, EncodingSchemeForm};

    /// Return value for `Core_nodeInfo` remote function.
    #[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
    pub(super) struct CoreNodeInfoPayload {
        #[serde(rename = "myAddr")]
        pub(super) my_addr: String,

        #[serde(rename = "encodingScheme")]
        pub(super) encoding_scheme: Vec<EncForm>,
    }

    #[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
    pub(super) struct EncForm {
        #[serde(rename = "prefixLen")]
        prefix_len: u8,

        #[serde(rename = "prefix")]
        prefix: String,

        #[serde(rename = "bitCount")]
        bit_count: u8,
    }

    impl TryFrom<EncForm> for EncodingSchemeForm {
        type Error = Error;

        fn try_from(form: EncForm) -> Result<Self, Self::Error> {
            let prefix = u32::from_str_radix(&form.prefix, 16).map_err(|e| anyhow!("bad prefix: {}", e))?;
            EncodingSchemeForm::try_new(form.bit_count, form.prefix_len, prefix).map_err(|e| anyhow!("bad encoding form: {}", e))
        }
    }

    pub(super) fn try_parse_encoding_scheme(encoding_scheme: Vec<EncForm>) -> Result<EncodingScheme, Error> {
        let encoding_forms = encoding_scheme.into_iter().map(EncForm::try_into).collect::<Result<Vec<_>, _>>()?;
        let encoding_scheme = EncodingScheme::try_new(&encoding_forms)?;
        Ok(encoding_scheme)
    }
}