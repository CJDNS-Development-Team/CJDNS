//! Local node (router) service task

#![allow(dead_code)] //TODO remove when done

use std::sync::Arc;
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Error;
use serde::{Deserialize, Serialize};
use tokio::select;

use cjdns_keys::CJDNS_IP6;
use cjdns_admin::ReturnValue;
use cjdns_admin::msgs::{GenericResponsePayload, Empty};
use cjdns_sniff::{ContentType, Message, ReceiveError, Sniffer, Content};
use cjdns_bencode::{BValue, BendyValue};

use crate::server::route::get_route;
use crate::server::Server;
use crate::utils::node::parse_node_name;
use crate::utils::timestamp::mktime;
use std::collections::BTreeMap;
use std::borrow::Cow;

pub(super) async fn service_task(server: Arc<Server>) {
    let res = do_service(server).await;
    if let Err(err) = res {
        error!("Failed to service local node: {}", err)
    }
}

async fn do_service(server: Arc<Server>) -> Result<(), Error> {
    let mut cjdns = cjdns_admin::connect(None).await?;

    // getting core node info and deserializing it to `node_info::NodeInfo`
    let raw_node_info = cjdns.invoke::<_, GenericResponsePayload>("Core_nodeInfo", Empty{}).await?;
    let node_info = node_info::parse(raw_node_info)?;

    // setting self node
    {
        let ipv6 = CJDNS_IP6::try_from(&node_info.key)?;
        let mut server_mut = server.mut_state.lock();
        server_mut.self_node = Some(Arc::new(server.nodes.new_node(
            node_info.version,
            node_info.key,
            Some(node_info.encoding_scheme),
            mktime(0xffffffffffffffffu64),
            ipv6,
            None,
        )?));
        println!("SELF NODE DATA {:?}", server_mut.self_node.as_ref().unwrap().encoding_scheme);
        println!("SELF NODE DATA {:?}", server_mut.self_node.as_ref().unwrap().ipv6);
        println!("SELF NODE DATA {:?}", server_mut.self_node.as_ref().unwrap().key);
    }

    warn!("Got selfNode");

    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

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

mod node_info {
    use std::convert::TryFrom;

    use anyhow::{Error, Result};

    use cjdns_admin::ReturnValue;
    use cjdns_admin::msgs::GenericResponsePayload;
    use cjdns_keys::CJDNSPublicKey;
    use cjdns_core::{EncodingScheme, EncodingSchemeForm};

    use crate::utils::node::parse_node_name;

    pub(super) struct NodeInfo {
        pub(super) version: u16,
        pub(super) key: CJDNSPublicKey,
        pub(super) encoding_scheme: EncodingScheme,
    }

    pub(super) fn parse(raw_node_info: GenericResponsePayload) -> Result<NodeInfo> {
        NodeInfo::try_from_payload(raw_node_info).map_err(|e| anyhow!("invalid node info: {}", e.to_string()))
    }

    impl NodeInfo {
        fn try_from_payload(raw_node_info: GenericResponsePayload) -> Result<Self> {
            // myAddr entry
            let node_name = Self::get_node_name(&raw_node_info)?;
            let (version, _, key) = parse_node_name(node_name)?;

            // encodingScheme entry
            let encoding_scheme_forms = Self::get_encoding_scheme_forms(&raw_node_info)?;
            let encoding_scheme = EncodingScheme::try_new(&encoding_scheme_forms).map_err(|e| Error::from(e))?;

            return Ok(NodeInfo { version, key, encoding_scheme });
        }

        fn get_node_name(raw_node_info: &GenericResponsePayload) -> Result<&str> {
            let my_addr_opt = raw_node_info.get("myAddr").map(ReturnValue::as_str);
            if let Some(addr_str_res) = my_addr_opt {
                return addr_str_res.map_err(|_| anyhow!("can't convert myAddr data to str"));
            }
            Err(anyhow!("can't get myAddr"))
        }

        fn get_encoding_scheme_forms(raw_node_info: &GenericResponsePayload) -> Result<Vec<EncodingSchemeForm>> {
            // converts response payload map value to encoding scheme form
            let to_scheme_form = |scheme_map: &ReturnValue| {
                let mut bit_count_opt = None;
                let mut prefix_opt = None;
                let mut prefix_len_opt = None;

                if let ReturnValue::Map(m) = scheme_map {
                    bit_count_opt = m.get("bitCount").map(ReturnValue::as_int);
                    prefix_opt = m.get("prefix").map(ReturnValue::as_str);
                    prefix_len_opt = m.get("prefixLen").map(ReturnValue::as_int);
                }

                if let (Some(Ok(bit_count)), Some(Ok(prefix)), Some(Ok(prefix_len))) = (bit_count_opt, prefix_opt, prefix_len_opt) {
                    let bit_count = u8::try_from(bit_count).map_err(|_| ())?;
                    let prefix = prefix.parse::<u32>().map_err(|_| ())?;
                    let prefix_len = u8::try_from(bit_count).map_err(|_| ())?;
                    return EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).map_err(|_| ())
                }
                Err(())
            };

            let scheme_forms_opt = raw_node_info.get("encodingScheme").map(|v| v.as_list(to_scheme_form));
            if let Some(scheme_forms_vec_res) = scheme_forms_opt {
                return scheme_forms_vec_res.map_err(|_| anyhow!("can't convert encodingScheme data to scheme forms"));
            }
            Err(anyhow!("can't get encodingScheme"))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ContentBenc {
    /// "protocol version"
    #[serde(rename = "p")]
    p: u32,

    /// transaction id
    #[serde(rename = "txid")]
    txid: Vec<u8>,

    #[serde(flatten)]
    body: QueryResponse,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum QueryResponse {
    Query {
        /// "snode query"
        #[serde(rename = "sq")]
        sq: Option<Vec<u8>>,

        /// for a "gr" (get-route) query, source
        #[serde(rename = "src")]
        src: Option<Vec<u8>>,

        /// for a "gr" (get-route) query, destination
        #[serde(rename = "tar")]
        tar: Option<Vec<u8>>,

        /// for an "ann" (announce) query, the announcement
        #[serde(rename = "ann")]
        ann: Option<Vec<u8>>,
    },

    Response {
        #[serde(rename = "recvTime")]
        recv_time: Option<u64>,

        #[serde(rename = "stateHash")]
        state_hash: Option<Vec<u8>>,

        #[serde(rename = "error")]
        error: Option<String>,

        #[serde(rename = "n")]
        n: Option<Vec<u8>>,

        #[serde(rename = "np")]
        np: Option<Vec<u8>>,
    },
}

/// Handles a massage from local node, and returns a response message that should be sent in return.
async fn on_subnode_message(server: Arc<Server>, msg: Message) -> Result<Option<Message>, Error> {
    let mut ret_msg = msg.clone();

    let mut content_benc_opt = None;
    let mut sq_opt = None;

    if let Content::Benc(content_benc) = &msg.content {
        content_benc_opt = Some(content_benc);
        if let Some(sq) = content_benc.get_dict_value("sq").map_err(|_| anyhow!("todo"))? {
            sq_opt = sq.as_string().ok();
        }
    }
    if content_benc_opt.is_none() || sq_opt.is_none() {
        return Ok(None);
    }

    let sq = sq_opt.expect("internal error: sq is none");
    let content_benc = content_benc_opt.expect("internal error: content benc is none");

    if msg.route_header.version != 0 {
        // no op
    } else if content_benc.get_dict_value("p").map_err(|_| anyhow!("todo"))?.is_none() {
        // no op
    } else {
        let p = content_benc.get_dict_value("p").map_err(|_| anyhow!("todo"))?.unwrap().as_int().unwrap();
        ret_msg.route_header.version = p as u32;
    }

    if msg.route_header.version == 0 || msg.route_header.public_key.is_none() || msg.route_header.ip6.is_none() {
        if msg.route_header.ip6.is_some() {
            warn!("message from {:?} with missing key or version {:?}", msg.route_header.ip6, msg);
        }
        return Ok(None)
    }
    server.mut_state.lock().current_node = msg.route_header.ip6.clone();
    let content_benc = match sq.as_str() {
        "gr" => {
            let mut dict = BTreeMap::new();
            if content_benc.get_dict_value("src").map_err(|_| anyhow!("todo"))?.is_none() {
                warn!("missing src");
                return Ok(None);
            }
            let src_ip = content_benc.get_dict_value("src").map_err(|_| anyhow!("todo"))?.unwrap().as_bytes().unwrap();
            let src_ip = CJDNS_IP6::try_from(src_ip.as_slice())?;
            if content_benc.get_dict_value("tar").map_err(|_| anyhow!("todo"))?.is_none() {
                warn!("missing tar");
                return Ok(None);
            }
            let tar_ip = content_benc.get_dict_value("tar").map_err(|_| anyhow!("todo"))?.unwrap().as_bytes().unwrap();
            let tar_ip = CJDNS_IP6::try_from(tar_ip.as_slice())?;
            let src = server.nodes.by_ip(&src_ip);
            let tar = server.nodes.by_ip(&tar_ip);

            let r = get_route(server.clone(), None, None);
            if let (Ok(route), Some(tar)) = (r, tar) {
                // use route here
                dict.insert(Cow::from("n".as_bytes()), BendyValue::Bytes(Cow::from(tar.key.to_vec())));
                let np_payload = {
                    let mut np = vec![1];
                    np.extend_from_slice(tar.version.to_be_bytes().as_ref());
                    np
                };
                dict.insert(Cow::from("np".as_bytes()), BendyValue::Bytes(Cow::from(np_payload)));
            }
            let recv_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            dict.insert(Cow::from("recvTime".as_bytes()), BendyValue::Integer(recv_time as i64));
            ret_msg.route_header.switch_header.label_shift = 0;
            Some(Content::Benc(BValue(BendyValue::Dict(dict))))
        },
        "ann" if content_benc.get_dict_value("ann").map_err(|_| anyhow!("todo"))?.is_some() => {
            let ann = content_benc.get_dict_value("ann").map_err(|_| anyhow!("todo"))?.unwrap().as_bytes().unwrap();
            let reply = server.handle_announce_impl(ann, true).await?;
            let (ann_hash, reply_err) = reply;
            if server.mut_state.lock().self_node.is_none() {
                return Err(anyhow!("todo"));
            }
            let mut dict = BTreeMap::new();
            let txid = content_benc.get_dict_value("txid").map_err(|_| anyhow!("todo"))?.unwrap().as_bytes().unwrap();
            dict.insert(Cow::from("txid".as_bytes()), BendyValue::Bytes(Cow::from(txid)));
            dict.insert(Cow::from("p".as_bytes()), BendyValue::Integer(server.mut_state.lock().self_node.clone().unwrap().version as i64));
            let recv_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            dict.insert(Cow::from("recvTime".as_bytes()), BendyValue::Integer(recv_time as i64));
            dict.insert(Cow::from("stateHash".as_bytes()), BendyValue::Bytes(Cow::from(ann_hash.clone().into_inner())));
            dict.insert(Cow::from("error".as_bytes()), BendyValue::Bytes(Cow::from(reply_err.to_string().as_bytes().to_vec())));
            ret_msg.route_header.switch_header.label_shift = 0;
            debug!("reply: {:?}", hex::encode(ann_hash.into_inner()));
            Some(Content::Benc(BValue(BendyValue::Dict(dict))))
        },
        "pn" => {
            let mut dict = BTreeMap::new();
            let recv_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            dict.insert(Cow::from("recvTime".as_bytes()), BendyValue::Integer(recv_time as i64));
            dict.insert(Cow::from("stateHash".as_bytes()), BendyValue::Bytes(Cow::from(vec![0; 64])));
            if ret_msg.route_header.ip6.is_none() {
                return Err(anyhow!("todo"));
            }
            if let Some(n) = server.nodes.by_ip(&ret_msg.route_header.ip6.as_ref().unwrap()) {
                let n_mut = n.mut_state.read();
                if let Some(state_hash) = &n_mut.state_hash {
                    dict.insert(Cow::from("stateHash".as_bytes()), BendyValue::Bytes(Cow::from(state_hash.clone().into_inner())));
                }
            }
            ret_msg.route_header.switch_header.label_shift = 0;
            Some(Content::Benc(BValue(BendyValue::Dict(dict))))
        },
        _ => {
            warn!("contentBenc {:?}", content_benc);
            None
        },
    };
    server.mut_state.lock().current_node = None;
    if let Some(benc) = content_benc {
        ret_msg.content = benc;
        warn!("RETURN MESSAGE {:?}", ret_msg);
        return Ok(Some(ret_msg));
    }
    Ok(None)
}