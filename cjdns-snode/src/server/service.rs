//! Local node (router) service task

#![allow(dead_code)] //TODO remove when done

use std::sync::Arc;
use std::convert::TryFrom;

use anyhow::Error;
use tokio::select;

use cjdns_keys::CJDNS_IP6;
use cjdns_admin::msgs::{GenericResponsePayload, Empty};
use cjdns_sniff::{ContentType, Message, ReceiveError, Sniffer};

use crate::server::route::get_route;
use crate::server::Server;
use crate::utils::timestamp::{mktime, now_u64};

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

    let ipv6 = CJDNS_IP6::try_from(&node_info.key)?;
    server.mut_state.lock().self_node = Some(Arc::new(server.nodes.new_node(
        node_info.version,
        node_info.key,
        Some(node_info.encoding_scheme),
        mktime(0xffffffffffffffffu64),
        ipv6,
        None,
    )?));

    warn!("Got selfNode");

    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

    // todo check connection impl after implementing new routes for test_srv

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

/// Handles a message from local node, and returns a response message that should be sent in return.
async fn on_subnode_message(server: Arc<Server>, msg: Message) -> Result<Option<Message>, Error> {
    let mut ret_msg = msg.clone();
    let msg_content_benc = content_benc::from(&mut ret_msg.content);

    let mut sq = None;
    if let Some(content) = msg_content_benc.as_ref() {
        if let Some(sq_res) = content.sq() {
            sq = Some(sq_res?);
        }
    }
    if msg_content_benc.is_none() || sq.is_none() {
        return Ok(None)
    }

    let mut msg_content_benc = msg_content_benc.expect("internal error: msg content isn't b-decoded");
    let sq = sq.expect("internal error: no 'sq' entry in benc content");

    if msg.route_header.version != 0 {
        // no op
    } else if let Some(p_res) =  msg_content_benc.p() {
        let p = p_res?;
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
                let src_ip = CJDNS_IP6::try_from(src_bytes.as_slice())?; // todo & instead of as slice
                src = server.nodes.by_ip(&src_ip);
            } else {
                warn!("missing src");
                return Ok(None);
            }

            if let Some(tar_bytes_res) = msg_content_benc.tar() {
                let tar_bytes = tar_bytes_res?;
                let tar_ip = CJDNS_IP6::try_from(tar_bytes.as_slice())?; // todo & instead of as slice
                tar = server.nodes.by_ip(&tar_ip);
            } else {
                warn!("missing tar");
                return Ok(None);
            }

            let r = get_route(server.clone(), src.clone(), tar.clone());
            if let (Ok(route), Some(tar)) = (r, tar) {
                // TODO use route here
                let n = tar.key.to_vec();
                let np = {
                    let mut np = vec![1];
                    np.extend_from_slice(&tar.version.to_be_bytes());
                    np
                };
                msg_content_benc.set("n", n.as_slice())?; // todo & instead of as slice
                msg_content_benc.set("np", np.as_slice())?; // todo & instead of as slice
            }
            msg_content_benc.set("recvTime", now_u64())?;
            ret_msg.route_header.switch_header.label_shift = 0;

            msg_content_benc.delete("sq");
            msg_content_benc.delete("src");
            msg_content_benc.delete("tar");
        },
        "ann" if msg_content_benc.ann().is_some() => {
            let ann = msg_content_benc.ann().expect("no 'ann' entry in benc content")?;
            let (ann_hash, reply_err) = server.handle_announce_impl(ann, true).await?;
            if let Some(node) = server.mut_state.lock().self_node.as_ref() {
                msg_content_benc.set("p", node.version)?;
                msg_content_benc.set("recvTime", now_u64())?;
                msg_content_benc.set("stateHash", ann_hash.bytes())?;
                msg_content_benc.set("error", reply_err.to_string())?;

                ret_msg.route_header.switch_header.label_shift = 0;
                debug!("reply: {:?}", hex::encode(ann_hash.bytes()));
            } else {
                return Err(anyhow!("self node isn't set"));
            }
        },
        "pn" => {
            msg_content_benc.set("recvTime", now_u64())?;
            msg_content_benc.set("stateHash", [0u8; 64].as_ref())?; // todo & instead of as ref

            if ret_msg.route_header.ip6.is_none() {
                return Err(anyhow!("route header ip6 is none"));
            }
            let ip6 = ret_msg.route_header.ip6.as_ref().expect("internal error: route header ip6 is none");
            if let Some(node) = server.nodes.by_ip(ip6) {
                if let Some(ann_hash) = node.mut_state.read().state_hash.as_ref() {
                    msg_content_benc.set("stateHash", ann_hash.bytes())?;
                }
            }

            ret_msg.route_header.switch_header.label_shift = 0;

            msg_content_benc.delete("sq");
            msg_content_benc.delete("src");
            msg_content_benc.delete("tar");
        },
        _ => {
            warn!("contentBenc {:?}", msg_content_benc);
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
    use std::fmt;

    use anyhow::{Result, Error};

    use cjdns_sniff::Content;
    use cjdns_bencode::{BValue, AsBValue};

    pub(super) fn from(content: &mut Content) -> Option<ContentBenc> {
        ContentBenc::try_from_content(content)
    }

    // Wrapper over message b-encoded content holding mutable reference to it.
    pub(super) struct ContentBenc<'a> {
        dict_content: &'a mut BValue,

        p: Option<BValue>,
        sq: Option<BValue>,
        src: Option<BValue>,
        tar: Option<BValue>,
        ann: Option<BValue>,
    }

    impl<'a> ContentBenc<'a> {
        pub(super) fn set<V: AsBValue>(&mut self, key: &'static str, value: V) -> Result<(), Error>{
            let value = value.as_bvalue().map_err(|_| anyhow!("setting value can't be b-encoded"))?;

            let _ = self.dict_content.set_dict_value(key, value.clone());
            self.update_matched_field(key, Some(value));
            Ok(())
        }

        pub(super) fn delete(&mut self, key: &'static str) {
            let _ = self.dict_content.delete_dict_value(key);
            self.update_matched_field(key, None);
        }

        pub(super) fn p(&self) -> Option<Result<i64>> {
            if let Some(p) = self.p.as_ref().map(BValue::as_int) {
                let p = p.map_err(|_| anyhow!("'p' isn't an int"));
                Some(p);
            }
            None
        }

        pub(super) fn sq(&self) -> Option<Result<String>> {
            if let Some(sq) = self.sq.as_ref().map(BValue::as_string) {
                let sq = sq.map_err(|_| anyhow!("'sq' value isn't a string"));
                return Some(sq);
            }
            None
        }

        pub(super) fn src(&self) -> Option<Result<Vec<u8>>> {
            if let Some(src) = self.src.as_ref().map(BValue::as_bytes) {
                let src = src.map_err(|_| anyhow!("can't convert 'src' value to bytes"));
                return Some(src);
            }
            None
        }

        pub(super) fn tar(&self) -> Option<Result<Vec<u8>>> {
            if let Some(tar) = self.tar.as_ref().map(BValue::as_bytes) {
                let tar = tar.map_err(|_| anyhow!("can't convert 'tar' value to bytes"));
                return Some(tar);
            }
            None
        }

        pub(super) fn ann(&self) -> Option<Result<Vec<u8>>> {
            if let Some(ann) = self.ann.as_ref().map(BValue::as_bytes) {
                let ann = ann.map_err(|_| anyhow!("can't convert 'ann' value to bytes"));
                return Some(ann);
            }
            None
        }

        fn try_from_content(content: &'a mut Content) -> Option<Self> {
            let create_content_benc = |dict_content: &'a mut BValue| -> Result<Self, ()> {
                let p = dict_content.get_dict_value("p")?;
                let sq = dict_content.get_dict_value("sq")?;
                let src = dict_content.get_dict_value("src")?;
                let tar = dict_content.get_dict_value("tar")?;
                let ann = dict_content.get_dict_value("ann")?;
                Ok(ContentBenc {dict_content, p, sq, src, tar, ann})
            };

            if let Content::Benc(bvalue) = content {
                if Self::is_dict(&bvalue) {
                    let ret = create_content_benc(bvalue).expect("internal error: bvalue isn't a dict");
                    return Some(ret);
                }
            }
            None
        }

        fn is_dict(bvalue: &BValue) -> bool {
            let test_query = bvalue.get_dict_value("non_existent_key");
            // test_query is Err(()) if bvalue is not a dict
            test_query.is_ok()
        }

        // Secures access to changed fields
        fn update_matched_field(&mut self, key: &'static str, value: Option<BValue>) {
            match key {
                "p" => self.p = value,
                "sq" => self.sq = value,
                "src" => self.src = value,
                "tar" => self.tar = value,
                "ann" => self.ann = value,
                _ => return
            }
        }
    }

    impl<'a> fmt::Debug for ContentBenc<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self.dict_content)
        }
    }
}