//! Local node (router) service task

#![allow(dead_code)] //TODO remove when done

use std::sync::Arc;
use std::convert::TryFrom;

use anyhow::Error;
use serde::{Deserialize, Serialize};
use tokio::select;

use cjdns_keys::CJDNS_IP6;
use cjdns_core::{EncodingScheme, EncodingSchemeForm};
use cjdns_admin::{ArgValues, ReturnValue, msgs::GenericResponsePayload};
use cjdns_sniff::{ContentType, Message, ReceiveError, Sniffer, Content};

use crate::server::route::get_route;
use crate::server::Server;
use crate::utils::node::parse_node_name;
use crate::utils::timestamp::mktime;

pub(super) async fn service_task(server: Arc<Server>) {
    let res = do_service(server).await;
    if let Err(err) = res {
        error!("Failed to service local node: {}", err)
    }
}

async fn do_service(server: Arc<Server>) -> Result<(), Error> {
    let mut cjdns = cjdns_admin::connect(None).await?;

    // setting self node
    let node_info = cjdns.invoke::<_, GenericResponsePayload>("Core_nodeInfo", ArgValues::default()).await?;

    let parsed_name = {
        let my_addr = node_info.get("myAddr").unwrap().as_str().unwrap();
        parse_node_name(my_addr.to_string()).unwrap()
    };
    let (version, _, key) = parsed_name;

    let ip6 = CJDNS_IP6::try_from(&key)?;

    let scheme_forms = node_info.get("encodingScheme").unwrap().as_list(|scheme_map| {
        match scheme_map {
            ReturnValue::Map(m) => {
                let bit_count = m.get("bitCount").unwrap().as_int().unwrap() as u8;
                let prefix = m.get("prefix").unwrap().as_str().unwrap().parse::<u32>().unwrap();
                let prefix_len = m.get("prefixLen").unwrap().as_int().unwrap() as u8;
                Ok(EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).unwrap())
            },
            _ => panic!("todo")
        }
    }).unwrap();
    let encoding_scheme = EncodingScheme::try_new(&scheme_forms)?;

    {
        let mut server_mut = server.mut_state.lock();
        server_mut.self_node = Some(Arc::new(server.nodes.new_node(
            version as u16,
            key,
            Some(encoding_scheme),
            mktime(0xffffffffffffffffu64),
            ip6,
            None,
        )?));
        println!("SELF NODE DATA {:?}", server_mut.self_node.as_ref().unwrap().encoding_scheme);
        println!("SELF NODE DATA {:?}", server_mut.self_node.as_ref().unwrap().ipv6);
        println!("SELF NODE DATA {:?}", server_mut.self_node.as_ref().unwrap().key);
    }

    warn!("Got selfNode");
    // let encoding_scheme = node_info.get("encodingScheme").unwrap().as_list();


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
async fn on_subnode_message(server: Arc<Server>, mut msg: Message) -> Result<Option<Message>, Error> {
    let mut content_benc_opt = None;
    let mut sq_opt = None;

    if let Content::Benc(b_val) = &mut msg.content {
        content_benc_opt = Some(b_val);
        if let Some(sq_bval_bytes) = b_val.get_dict_value("sq").map_err(|_| anyhow!("todo"))? {
            sq_opt = sq_bval_bytes.as_string().ok();
        }
    } else {
        return Ok(None)
    }
    if sq_opt.is_none() { return Ok(None); }
    let sq = sq_opt.expect("internal error: sq is none");
    let content_benc = content_benc_opt.expect("internal error: content benc is none");

    if msg.route_header.version != 0 {
        // no op
    } else if content_benc.get_dict_value("p").map_err(|_| anyhow!("todo"))?.is_none() {
        // no op
    } else {
        let p = content_benc.get_dict_value("p").map_err(|_| anyhow!("todo"))?.unwrap().as_int().unwrap();
        msg.route_header.version = p as u32;
    }
    if msg.route_header.version == 0 || msg.route_header.public_key.is_none() || msg.route_header.ip6.is_none() {
        if msg.route_header.ip6.is_some() {
            warn!("message from {:?} with missing key or version {:?}", msg.route_header.ip6, msg);
        }
        return Ok(None)
    }
    server.mut_state.lock().current_node = msg.route_header.ip6;
    let ret_msg = match sq.as_str() {
        "gr" => {
            if content_benc.get_dict_value("src").map_err(|_| anyhow!("todo"))?.is_none() {
                warn!("missing src");
                Ok(None)
            }
            let src_ip = content_benc.get_dict_value("src").map_err(|_| anyhow!("todo"))?.unwrap().as_string().unwrap();
            let src_ip = CJDNS_IP6::try_from(src_ip.as_str())?;
            if content_benc.get_dict_value("tar").map_err(|_| anyhow!("todo"))?.is_none() {
                warn!("missing tar");
                Ok(None)
            }
            let tar_ip = content_benc.get_dict_value("tar").map_err(|_| anyhow!("todo"))?.unwrap().as_string().unwrap();
            let tar_ip = CJDNS_IP6::try_from(tar_ip.as_str())?;
            let src = server.nodes.by_ip(&src_ip);
            let tar = server.nodes.by_ip(&tar_ip);

            let r = get_route(server.clone(), None, None);
            if let Ok(route) = r {
                // some stuff here
            }
            // new msg here
            return Ok(Some(msg.clone()));
        },
        "ann" if content_benc.get_dict_value("ann").map_err(|_| anyhow("todo"))?.is_some() => {
            let ann = content_benc.get_dict_value("ann").map_err(|_| anyhow("todo"))?.unwrap().as_bytes().unwrap();
            let reply = server.handle_announce_impl(ann, true).await?;
            let (ann_hash, reply_err) = reply;
            if server.mut_state.lock().self_node.is_none() {
                return Err(anyhow("todo"));
            }
            // new msg here
            return Ok(Some(msg.clone()));
        },
        "pn" => {
            // new msg here
        },
        _ => {
            warn!("contentBenc", content_benc);
            None
        },
    };
    server.mut_state.lock().current_node = None;
    Err(anyhow!("jff"))
}