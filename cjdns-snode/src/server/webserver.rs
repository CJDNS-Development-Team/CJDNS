//! Web server

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use warp::{Filter, Rejection, Reply};

use crate::server::Server;

pub(super) async fn test_srv_task(server: Arc<Server>) {
    let routes = api(server);
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}

fn api(server: Arc<Server>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone {
    // endpoint '/'
    let info = info_route(server.clone());
    let debug_node = debug_node_route(server.clone());
    let dump = dump_route(server.clone());

    // endpoint '/cjdnsnode_websocket'
    let ws = ws_route(server.clone());

    info.or(debug_node).or(dump).or(ws)
}

fn info_route(server: Arc<Server>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone {
    warp::path::end()
        .and(with_server(server))
        .and_then(handlers::handle_info)
}

fn debug_node_route(server: Arc<Server>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone {
    warp::path::path("debugnode")
        .and(warp::path::param())
        .and(with_server(server))
        .and_then(handlers::handle_debug_node)
}

fn dump_route(server: Arc<Server>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone {
    let dump_header = warp::reply::with::header("content-type", "application/octet-stream");
    warp::path::path("dump")
        .and(with_server(server))
        .and_then(handlers::handle_dump)
        .with(dump_header)
}

fn ws_route(server: Arc<Server>) -> impl Filter<Extract=impl Reply, Error=Rejection> + Clone {
    warp::path::path("cjdnsnode_websocket")
        .and(warp::addr::remote())
        .and(with_server(server))
        .and(warp::ws())
        .map(|addr: Option<SocketAddr>, server: Arc<Server>, ws_manager: warp::ws::Ws| {
            let addr = addr.expect("no remote addr");
            let addr = addr.to_string();
            let peers = Arc::clone(&server.peers);
            ws_manager.on_upgrade(move |ws_conn| async move {
                let res = peers.accept_incoming_connection(addr, ws_conn).await;
                if let Err(err) = res {
                    warn!("WebSocket error: {}", err);
                }
            })
        })
}

fn with_server(server: Arc<Server>) -> impl Filter<Extract=(Arc<Server>,), Error=Infallible> + Clone {
    warp::any().map(move || server.clone())
}

mod handlers {
    use std::convert::{Infallible, TryFrom};
    use std::sync::Arc;

    use serde::Serialize;
    use thiserror::Error;
    use warp::{http::StatusCode, Rejection, reply, Reply};
    use warp::reject::Reject;

    use cjdns_keys::CJDNS_IP6;

    use crate::peer::PeersInfo;
    use crate::server::Server;

    #[derive(Error, Debug)]
    enum WebServerError {
        #[error("Invalid IPv6 address")]
        BadIP6Address,
    }

    impl Reject for WebServerError {}

    #[derive(Serialize)]
    struct InfoReply {
        peers_info: PeersInfo,
        nodes_count: usize
    }

    pub(super) async fn handle_info(server: Arc<Server>) -> Result<impl Reply, Infallible> {
        let reply = InfoReply {
            peers_info: server.peers.get_info(),
            nodes_count: server.nodes.count()
        };
        Ok(reply::json(&reply))
    }

    pub(super) async fn handle_debug_node(ip6: String, server: Arc<Server>) -> Result<StatusCode, Rejection> {
        let ip = CJDNS_IP6::try_from(ip6.as_str()).map_err(|_| warp::reject::custom(WebServerError::BadIP6Address))?;
        server.mut_state.lock().debug_node = Some(ip);
        return Ok(StatusCode::OK);
    }

    pub(super) async fn handle_dump(server: Arc<Server>) -> Result<Vec<u8>, Infallible> {
        Ok(server.nodes.anns_dump())
    }
}