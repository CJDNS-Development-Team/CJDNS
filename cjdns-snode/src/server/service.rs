//! Local node (router) service task

#![allow(dead_code)] //TODO remove when done

use std::sync::Arc;

use anyhow::Error;
use serde::{Deserialize, Serialize};
use tokio::select;

use cjdns_sniff::{ContentType, Message, ReceiveError, Sniffer};

use crate::server::route::get_route;
use crate::server::Server;

pub(super) async fn service_task(server: Arc<Server>) {
    let res = do_service(server).await;
    if let Err(err) = res {
        error!("Failed to service local node: {}", err)
    }
}

async fn do_service(server: Arc<Server>) -> Result<(), Error> {
    let cjdns = cjdns_admin::connect(None).await?;

    //TODO call Core_nodeInfo remote func
    //TODO as a start, use `./target/debug/cjdnsadmin 'Core_nodeInfo()'` to see how the response looks like

    let mut sniffer = Sniffer::sniff_traffic(cjdns, ContentType::Cjdht).await?;

    loop {
        select! {
            msg = sniffer.receive() => {
                match msg {
                    Ok(msg) => {
                        let ret_msg = on_subnode_message(server.clone(), msg).await?;
                        sniffer.send(ret_msg, None).await?;
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
async fn on_subnode_message(server: Arc<Server>, msg: Message) -> Result<Message, Error> {
    let _ = get_route(server.clone(), None, None);
    todo!()
}