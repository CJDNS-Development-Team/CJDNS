//! Web server

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use warp::{Filter, Rejection, Reply};

use crate::server::Server;

pub(super) async fn test_srv_task(server: Arc<Server>) {
    let routes = api(server);
    warp::serve(routes).run(([127, 0, 0, 1], 3333)).await;
}

fn api(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    // endpoint '/'
    let info = info_route(server.clone());
    let debug_node = debug_node_route(server.clone());
    let dump = dump_route(server.clone());
    let path = path_route(server.clone());
    let ni = ni_with_ip_route(server.clone()).or(ni_empty(server.clone()));
    let walk = walk_route(server.clone());
    // endpoint '/cjdnsnode_websocket'
    let ws = ws_route(server.clone());

    info.or(debug_node).or(dump).or(path).or(ni).or(walk).or(ws)
}

fn info_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::end().and(with_server(server)).and_then(handlers::handle_info)
}

fn debug_node_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::path("debugnode")
        .and(warp::path::param())
        .and(with_server(server))
        .and_then(handlers::handle_debug_node)
}

fn dump_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let dump_header = warp::reply::with::header("content-type", "application/octet-stream");
    warp::path::path("dump")
        .and(with_server(server))
        .and_then(handlers::handle_dump)
        .with(dump_header)
}

fn path_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::path("path")
        .and(warp::path::param())
        .and(warp::path::param())
        .and(with_server(server))
        .and_then(handlers::handle_path)
}

fn ni_with_ip_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::path("ni")
        .and(warp::path::param())
        .and(with_server(server))
        .and_then(handlers::handle_ni_with_ip)
}

fn ni_empty(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::path("ni")
        .and(warp::path::end())
        .and(with_server(server))
        .and_then(handlers::handle_ni_empty)
}

fn walk_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::path("walk").and(with_server(server)).and_then(handlers::handle_walk)
}

fn ws_route(server: Arc<Server>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path::path("cjdnsnode_websocket")
        .and(warp::addr::remote())
        .and(with_server(server))
        .and(warp::ws())
        .map(|addr: Option<SocketAddr>, server: Arc<Server>, ws_manager: warp::ws::Ws| {
            let addr = addr.expect("no remote addr").ip().to_string();
            let peers = Arc::clone(&server.peers);
            ws_manager.on_upgrade(move |ws_conn| async move {
                let res = peers.accept_incoming_connection(addr, ws_conn).await;
                if let Err(err) = res {
                    warn!("WebSocket error: {}", err);
                }
            })
        })
}

fn with_server(server: Arc<Server>) -> impl Filter<Extract = (Arc<Server>,), Error = Infallible> + Clone {
    warp::any().map(move || server.clone())
}

mod handlers {
    use std::collections::BTreeMap;
    use std::convert::{Infallible, TryFrom};
    use std::sync::Arc;

    use serde_json::json;
    use serde_json::Value as JsonValue;
    use thiserror::Error;
    use warp::reject::Reject;
    use warp::{http::StatusCode, Rejection, Reply};

    use cjdns_ann::{Announcement, Entity};
    use cjdns_core::{EncodingScheme, RoutingLabel};
    use cjdns_keys::CJDNS_IP6;

    use crate::server::{route::get_route, Server};
    use crate::utils::timestamp::make_timestamp;

    use super::node_info::nodes_info;

    use self::warp_pretty_print_json_reply::reply_json;

    #[derive(Error, Debug)]
    enum WebServerError {
        #[error("Bad IPv6 address '{0}': {1}")]
        BadIP6Address(String, String),
    }

    impl Reject for WebServerError {}

    pub(super) async fn handle_info(server: Arc<Server>) -> Result<impl Reply, Infallible> {
        let peers_info = server.peers.get_info();
        let nodes_count = server.nodes.count();

        let reply = json! {{
            "peer": json!{{
                "peers": peers_info.peers.into_iter().map(|pi| {
                    json!{{
                        "addr": pi.addr,
                        "outstandingRequests": pi.outstanding_requests,
                        "msgsOnWire": pi.msgs_on_wire,
                        "msgQueue": pi.msg_queue,
                    }}
                }).collect::<Vec<_>>(),
                "announcements": peers_info.announcements,
                "annByHashLen": peers_info.ann_by_hash_len,
            }},
            "nodesByIp": nodes_count,
        }};

        Ok(reply_json(&reply))
    }

    pub(super) async fn handle_debug_node(ip6: String, server: Arc<Server>) -> Result<StatusCode, Rejection> {
        let ip = CJDNS_IP6::try_from(ip6.as_str()).map_err(|e| warp::reject::custom(WebServerError::BadIP6Address(ip6, e.to_string())))?;
        server.mut_state.lock().debug_node = Some(ip);
        return Ok(StatusCode::OK);
    }

    pub(super) async fn handle_dump(server: Arc<Server>) -> Result<Vec<u8>, Infallible> {
        Ok(server.nodes.anns_dump())
    }

    pub(super) async fn handle_path(src: String, tar: String, server: Arc<Server>) -> Result<impl Reply, Rejection> {
        let src_ip = CJDNS_IP6::try_from(src.as_str()).map_err(|e| warp::reject::custom(WebServerError::BadIP6Address(src, e.to_string())))?;
        let tar_ip = CJDNS_IP6::try_from(tar.as_str()).map_err(|e| warp::reject::custom(WebServerError::BadIP6Address(tar, e.to_string())))?;
        let src = server.nodes.by_ip(&src_ip);
        let tar = server.nodes.by_ip(&tar_ip);
        warn!("http getRoute req {} {}", src_ip, tar_ip);
        if src.is_none() {
            return Ok("src not found".to_string());
        }
        if tar.is_none() {
            return Ok("tar not found".to_string());
        }
        match get_route(server.clone(), src, tar) {
            Ok(r) => Ok(serde_json::to_string_pretty(&r).unwrap()),
            Err(e) => Ok(format!("{:?}", e)),
        }
    }

    pub(super) async fn handle_ni_with_ip(ip6: String, server: Arc<Server>) -> Result<impl Reply, Infallible> {
        if let Ok(ip6) = CJDNS_IP6::try_from(ip6.as_str()) {
            if let Some(node) = server.nodes.by_ip(&ip6) {
                let node_state = node.mut_state.read();

                let reply = json! {{
                    "node": json!{{
                        "type": format!("{:?}", node.node_type),
                        "version": node.version,
                        "key": node.key.to_string(),
                        "ipv6": node.ipv6.to_string(),
                        "encodingScheme": json_encoding_scheme(&node.encoding_scheme),
                        "inwardLinksByIp": node.inward_links_by_ip.lock().iter().map(|(ip6, links)| {
                            let links = links.iter().map(|link| {
                                let link_state = link.mut_state.lock();
                                json!{{
                                    "label": json_label(Some(link.label)),
                                    "encodingFormNum": link.encoding_form_number,
                                    "peerNum": link.peer_num,
                                    "linkState": link.link_state.lock().iter().map(|(&time, state)| {
                                        let state = json!{{
                                            "drops": state.drops,
                                            "lag": state.lag,
                                            "kbRecv": state.kb_recv,
                                        }};
                                        (time, state)
                                    }).collect::<BTreeMap<_, _>>(),
                                    "mut": json!{{
                                        "time": link_state.time,
                                        "mtu": link_state.mtu,
                                        "value": link_state.value,
                                        "flags": link_state.flags,
                                    }},
                                }}
                            });
                            (ip6.to_string(), links.collect::<Vec<_>>())
                        }).collect::<BTreeMap<_, _>>(),
                        "mut": json!{{
                            "timestamp": format!("{:x}", make_timestamp(node_state.timestamp)),
                            "announcements": node_state.announcements.iter().map(json_announcement).collect::<Vec<_>>(),
                            "stateHash": node_state.state_hash.as_ref().map(|buf| json_binary_buffer(buf.bytes())),
                            "resetMsg": node_state.reset_msg.as_ref().map(json_announcement),
                        }},
                    }},
                }};
                return Ok(reply_json(&reply));
            }
        }
        let reply = json! {{}};
        return Ok(reply_json(&reply));
    }

    pub(super) async fn handle_ni_empty(server: Arc<Server>) -> Result<impl Reply, Infallible> {
        let nodes_info = nodes_info(&server.nodes);
        let peers_info = server.peers.get_info();

        let reply = json! {{
            "totalNodes": nodes_info.nodes.len(),
            "nodes": nodes_info.nodes.into_iter().map(|ni| {
                json!{{
                    "ip6": ni.ip6,
                    "announcements": ni.announcements,
                    "rst": ni.rst,
                }}
            }).collect::<Vec<_>>(),
            "totalAnnouncements": nodes_info.total_ann,
            "totalWithRsts": nodes_info.total_ann + nodes_info.resets,
            "peerInfo": json!{{
                "peers": peers_info.peers.into_iter().map(|pi| {
                    json!{{
                        "addr": pi.addr,
                        "outstandingRequests": pi.outstanding_requests,
                        "msgsOnWire": pi.msgs_on_wire,
                        "msgQueue": pi.msg_queue,
                    }}
                }).collect::<Vec<_>>(),
                "announcements": peers_info.announcements,
                "annByHashLen": peers_info.ann_by_hash_len,
            }},
        }};

        return Ok(reply_json(&reply));
    }

    pub(super) async fn handle_walk(server: Arc<Server>) -> Result<impl Reply, Infallible> {
        let mut out = Vec::new();
        let mut out_links = Vec::new();
        for ip in server.nodes.all_ips() {
            if let Some(node) = server.nodes.by_ip(&ip) {
                let walk_node = json!([
                    "node".to_string(),
                    make_timestamp(node.mut_state.read().timestamp) / 1000,
                    "-".to_string(),
                    format!("v{}.{}.{}", node.version, RoutingLabel::<u64>::self_reference(), node.key),
                    json_encoding_scheme(&node.encoding_scheme),
                    node.ipv6.to_string(),
                ]);
                out.push(walk_node);

                for (peer_ip, links) in node.inward_links_by_ip.lock().iter() {
                    if let Some(other_node) = server.nodes.by_ip(peer_ip) {
                        for link in links {
                            let walk_link = json!([
                                "link".to_string(),
                                link.mut_state.lock().time / 1000,
                                "-".to_string(),
                                node.key.to_string(),
                                other_node.key.to_string(),
                                json_label(Some(link.label)),
                            ]);
                            out_links.push(walk_link)
                        }
                    }
                }
            }
        }

        out.append(&mut out_links);
        let out = out
            .iter()
            .map(|v| serde_json::to_string(v).expect("internal error: value isn't serializable"))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(out)
    }

    fn json_encoding_scheme(encoding_scheme: &EncodingScheme) -> JsonValue {
        json!(encoding_scheme
            .iter()
            .map(|form| {
                let (bit_count, prefix_len, prefix) = form.params();
                json! {{
                    "bitCount": bit_count,
                    "prefix": format!("{:x}", prefix),
                    "prefixLen": prefix_len,
                }}
            })
            .collect::<Vec<_>>())
    }

    fn json_label(label: Option<RoutingLabel<u32>>) -> JsonValue {
        let s = if let Some(label) = label {
            let bits = label.bits() as u64;
            let label = RoutingLabel::try_new(bits).expect("internal error: zero label");
            label.to_string()
        } else {
            "0000.0000.0000.0000".to_string()
        };
        json!(s)
    }

    fn json_announcement(ann: &Announcement) -> JsonValue {
        json! {{
            "signature": ann.header.signature,
            "pubSigningKey": ann.header.pub_signing_key,
            "snodeIp": ann.header.snode_ip.to_string(),
            "nodePubKey": ann.node_pub_key.to_string(),
            "nodeIp": ann.node_ip.to_string(),
            "ver": ann.header.version,
            "isReset": ann.header.is_reset,
            "timestamp": format!("{:x}", ann.header.timestamp),
            "entities": ann.entities.iter().map(json_ann_entity).collect::<Vec<_>>(),
            "binary": json_binary_buffer(&ann.binary),
            "hash": hex::encode(ann.hash.bytes()),
        }}
    }

    fn json_ann_entity(entity: &Entity) -> JsonValue {
        match *entity {
            Entity::NodeProtocolVersion(v) => {
                json! {{
                    "type": "Version",
                    "version": v,
                }}
            }
            Entity::EncodingScheme { ref hex, ref scheme } => {
                json! {{
                    "type": "EncodingScheme",
                    "hex": hex.clone(),
                    "scheme": json_encoding_scheme(scheme),
                }}
            }
            Entity::Peer(ref peer_data) => {
                json! {{
                    "type": "Peer",
                    "ipv6": peer_data.ipv6.to_string(),
                    "label": json_label(peer_data.label),
                    "mtu": peer_data.mtu,
                    "peerNum": peer_data.peer_num,
                    "unused": peer_data.unused,
                    "encodingFormNum": peer_data.encoding_form_number,
                    "flags": peer_data.flags,
                }}
            }
            Entity::LinkState(ref ls_data) => {
                json! {{
                    "type": "LinkState",
                    "nodeId": ls_data.node_id,
                    "startingPoint": ls_data.starting_point,
                    "lagSlots": ls_data.lag_slots,
                    "dropSlots": ls_data.drop_slots,
                    "kvRecvSlots": ls_data.kb_recv_slots,
                }}
            }
        }
    }

    fn json_binary_buffer(buf: &[u8]) -> JsonValue {
        json! {{
            "type": "Buffer",
            "data": buf.to_vec(),
        }}
    }

    /// Copy of `warp::reply::json`, but with pretty json formatter.
    mod warp_pretty_print_json_reply {
        use serde::Serialize;
        use warp::http::{header::CONTENT_TYPE, HeaderValue, StatusCode};
        use warp::reply::{Reply, Response};

        /// Copy of warp::reply::json, but with pretty json formatter
        pub(super) fn reply_json<S: Serialize>(val: &S) -> Json {
            Json {
                inner: serde_json::to_vec_pretty(val).map_err(|e| error!("json error {}", e)),
            }
        }

        pub(super) struct Json {
            inner: Result<Vec<u8>, ()>,
        }

        impl Reply for Json {
            #[inline]
            fn into_response(self) -> Response {
                match self.inner {
                    Ok(body) => {
                        let mut res = Response::new(body.into());
                        res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                        res
                    }
                    Err(()) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
        }
    }
}

mod node_info {
    use crate::server::nodes::Nodes;

    pub(super) struct NodesInfo {
        pub(super) nodes: Vec<NodeShortInfo>,
        pub(super) total_ann: u64,
        pub(super) resets: u64,
    }

    pub(super) struct NodeShortInfo {
        pub(super) ip6: String,
        pub(super) announcements: u64,
        pub(super) rst: bool,
    }

    pub(super) fn nodes_info(nodes: &Nodes) -> NodesInfo {
        let mut total_ann = 0;
        let mut resets = 0;
        let nodes = nodes
            .all_ips()
            .iter()
            .filter_map(|ip6| {
                // Skip nodes that just disappeared
                nodes.by_ip(ip6).map(|node| (ip6, node))
            })
            .map(|(ip6, node)| {
                let node_state = node.mut_state.read();
                let announcements = node_state.announcements.len() as u64;
                total_ann += announcements;
                let rst = node_state.reset_msg.is_some() && node_state.announcements.iter().all(|ann| Some(ann) != node_state.reset_msg.as_ref());
                if rst {
                    resets += 1;
                }
                NodeShortInfo {
                    ip6: ip6.to_string(),
                    announcements,
                    rst,
                }
            })
            .collect::<Vec<_>>();

        NodesInfo { nodes, total_ann, resets }
    }
}
