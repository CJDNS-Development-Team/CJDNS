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
use cjdns_bencode::{BValue, BendyValue, to_bytes};

use crate::server::route::get_route;
use crate::server::Server;
use crate::utils::node::parse_node_name;
use crate::utils::timestamp::{mktime, now_u64};
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

    // setting self node
    let raw_node_info = cjdns.invoke::<_, GenericResponsePayload>("Core_nodeInfo", Empty{}).await?;
    let node_info = node_info::parse(raw_node_info)?;
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
    }
    warn!("Got selfNode");

    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

    // todo checking connection

    // handling subnode message
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

/// Handles a massage from local node, and returns a response message that should be sent in return.
async fn on_subnode_message(server: Arc<Server>, msg: Message) -> Result<Option<Message>, Error> {
    let mut ret_msg = msg.clone();
    let ret_content_benc = content_benc::create_content_builder(&mut ret_msg.content);
    let msg_content_benc = content_benc::parse(&msg.content);

    // comment for Alex: I know we could do it differently, but I tried to follow js impl style
    if msg_content_benc.is_none() {
        return Ok(None)
    }
    let msg_content_benc = msg_content_benc.expect("internal error: msg content isn't b-decoded");

    if msg_content_benc.sq().is_none() {
        return Ok(None)
    }
    let sq = msg_content_benc.sq().expect("internal error: no 'sq' entry in benc content")?;

    if msg.route_header.version != 0 {
        // no op
    } else if msg_content_benc.p().is_none() {
        // no op
    } else {
        let p = msg_content_benc.p().expect("internal error: no 'p' entry in benc content")?;
        ret_msg.route_header.version = u32::try_from(p)?;
    }

    if msg.route_header.version == 0 || msg.route_header.public_key.is_none() || msg.route_header.ip6.is_none() {
        if msg.route_header.ip6.is_some() {
            warn!("message from {:?} with missing key or version {:?}", msg.route_header.ip6, msg);
        }
        return Ok(None)
    }

    server.mut_state.lock().current_node = msg.route_header.ip6.clone();
    match sq.as_str() {
        "gr" => {
            let mut src = None;
            let mut tar = None;

            if let Some(src_bytes_res) = msg_content_benc.src() {
                let src_bytes = src_bytes_res?;
                let src_ip = CJDNS_IP6::try_from(src_bytes)?;
                src = server.nodes.by_ip(&src_ip);
            } else {
                warn!("missing src");
                return Ok(None);
            }

            if let Some(tar_bytes_res) = msg_content_benc.tar() {
                let tar_bytes = tar_bytes_res?;
                let tar_ip = CJDNS_IP6::try_from(tar_bytes)?;
                tar = server.nodes.by_ip(&tar_ip);
            } else {
                warn!("missing tar");
                return Ok(None);
            }

            let r = get_route(server.clone(), src.clone(), tar.clone());
            if let (Ok(route), Some(tar)) = (r, tar) {
                // use route here
                let n = tar.key.to_vec();
                let np = {
                    let mut np = vec![1];
                    np.extend_from_slice(tar.version.to_be_bytes().as_ref());
                    np
                };
                ret_content_benc

                // ret_content_benc.set/ ret_content_benc.delete
            }
            let recv_time = now_u64();
            // ret_content_benc.set/ ret_content_benc.delete
            ret_msg.route_header.switch_header.label_shift = 0;
            // returns nothing
        },
        // "ann" if content_benc.get_dict_value("ann").map_err(|_| anyhow!("todo"))?.is_some() => {
        //     let ann = content_benc.get_dict_value("ann").map_err(|_| anyhow!("todo"))?.unwrap().as_bytes().unwrap();
        //     let reply = server.handle_announce_impl(ann, true).await?;
        //     let (ann_hash, reply_err) = reply;
        //     if server.mut_state.lock().self_node.is_none() {
        //         return Err(anyhow!("todo"));
        //     }
        //     let mut dict = BTreeMap::new();
        //     let txid = content_benc.get_dict_value("txid").map_err(|_| anyhow!("todo"))?.unwrap().as_bytes().unwrap();
        //     dict.insert(Cow::from("txid".as_bytes()), BendyValue::Bytes(Cow::from(txid)));
        //     dict.insert(Cow::from("p".as_bytes()), BendyValue::Integer(server.mut_state.lock().self_node.clone().unwrap().version as i64));
        //     let recv_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        //     dict.insert(Cow::from("recvTime".as_bytes()), BendyValue::Integer(recv_time as i64));
        //     dict.insert(Cow::from("stateHash".as_bytes()), BendyValue::Bytes(Cow::from(ann_hash.clone().into_inner())));
        //     dict.insert(Cow::from("error".as_bytes()), BendyValue::Bytes(Cow::from(reply_err.to_string().as_bytes().to_vec())));
        //     ret_msg.route_header.switch_header.label_shift = 0;
        //     debug!("reply: {:?}", hex::encode(ann_hash.into_inner()));
        //     Some(Content::Benc(BValue(BendyValue::Dict(dict))))
        // },
        // "pn" => {
        //     let mut dict = BTreeMap::new();
        //     let recv_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        //     dict.insert(Cow::from("recvTime".as_bytes()), BendyValue::Integer(recv_time as i64));
        //     dict.insert(Cow::from("stateHash".as_bytes()), BendyValue::Bytes(Cow::from(vec![0; 64])));
        //     if ret_msg.route_header.ip6.is_none() {
        //         return Err(anyhow!("todo"));
        //     }
        //     if let Some(n) = server.nodes.by_ip(&ret_msg.route_header.ip6.as_ref().unwrap()) {
        //         let n_mut = n.mut_state.read();
        //         if let Some(state_hash) = &n_mut.state_hash {
        //             dict.insert(Cow::from("stateHash".as_bytes()), BendyValue::Bytes(Cow::from(state_hash.clone().into_inner())));
        //         }
        //     }
        //     ret_msg.route_header.switch_header.label_shift = 0;
        //     Some(Content::Benc(BValue(BendyValue::Dict(dict))))
        // },
        _ => {
            warn!("contentBenc {:?}", content_benc);
            None
        },
    };
    server.mut_state.lock().current_node = None;
    Ok(Some(ret_msg))
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

mod content_benc {
    use std::convert::TryFrom;

    use anyhow::{Result, Error};

    use cjdns_sniff::Content;
    use cjdns_bencode::BValue;

    pub(super) fn parse(content: &Content) -> Option<ContentBencQuery> {
        ContentBencQuery::try_from_content(&content)
    }

    pub(super) fn create_content_builder(content: &mut Content) {
        todo!()
    }

    pub(super) struct ContentBencQuery {
        p: Option<BValue>,
        txid: Option<BValue>,
        sq: Option<BValue>,
        src: Option<BValue>,
        tar: Option<BValue>,
        ann: Option<BValue>,
    }

    impl ContentBencQuery {
        pub fn p(&self) -> Option<Result<i64>> {
            if let Some(p) = self.p.as_ref().map(BValue::as_int) {
                let p = p.map_err(|_| anyhow!("'p' isn't an int"));
                Some(p);
            }
            None
        }

        pub fn sq(&self) -> Option<Result<String>> {
            if let Some(sq) = self.sq.as_ref().map(BValue::as_string) {
                let sq = sq.map_err(|_| anyhow!("'sq' value isn't a string"));
                return Some(sq);
            }
            None
        }

        pub fn src(&self) -> Option<Result<Vec<u8>>> {
            if let Some(src) = self.src.as_ref().map(BValue::as_bytes) {
                let src = src.map_err(|_| anyhow!("can't convert 'src' value to bytes"));
                return Some(src);
            }
            None
        }

        pub fn tar(&self) -> Result<Vec<u8>> {
            if let Some(tar) = self.tar.as_ref().map(BValue::as_bytes) {
                let tar = tar.map_err(|_| anyhow!("can't convert 'tar' value to bytes"))?;
                return Ok(tar);
            }
            Err(anyhow!("no 'tar' entry in benc content"))
        }

        pub fn ann(&self) -> Result<Vec<u8>> {
            if let Some(ann) = self.ann.as_ref().map(BValue::as_bytes) {
                let ann = ann.map_err(|_| anyhow!("can't convert 'ann' value to bytes"))?;
                return Ok(ann);
            }
            Err(anyhow!("no 'ann' entry in benc content"))
        }

        fn try_from_content(content: &Content) -> Option<Self> {
            let create_content_benc = |dict_bvalue: &BValue| -> Result<Self, ()> {
                let p = dict_bvalue.get_dict_value("p")?;
                let txid = dict_bvalue.get_dict_value("txid")?;
                let sq = dict_bvalue.get_dict_value("sq")?;
                let src = dict_bvalue.get_dict_value("src")?;
                let tar = dict_bvalue.get_dict_value("tar")?;
                let ann = dict_bvalue.get_dict_value("ann")?;
                Ok(ContentBencQuery {p, txid, sq, src, tar, ann})
            };

            if let Content::Benc(bvalue) = content {
                if Self::is_dict_bvalue(&bvalue) {
                    let ret = create_content_benc(bvalue).expect("internal error: bvalue isn't a dict");
                    return Some(ret);
                }
            }
            None
        }

        fn is_dict_bvalue(bvalue: &BValue) -> bool {
            let nonexistent_key = "nonexistent_key";
            // returns Err(()) if bvalue is not a dict
            bvalue.get_dict_value(nonexistent_key).is_ok()
        }
    }
}