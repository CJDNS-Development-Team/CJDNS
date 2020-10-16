//! Websockets - unification of incoming and outgoing connections

use anyhow::Error;
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use futures::future::ready;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::WebSocketStream;
use warp::ws::WebSocket;

pub type WsWrite = dyn Sink<Vec<u8>, Error=Error> + Unpin + Send;
pub type WsRead = dyn Stream<Item=Result<Vec<u8>, Error>> + Unpin + Send;

pub trait WebSock {
    fn ws_split(self) -> (Box<WsWrite>, Box<WsRead>);
}

impl WebSock for WebSocketStream<TcpStream> {
    fn ws_split(self) -> (Box<WsWrite>, Box<WsRead>) {
        let (ws_write, ws_read) = self.split();
        let ws_write = ws_write.with(|bytes| ready(Ok(tungstenite::Message::Binary(bytes)))).sink_map_err(|err: tungstenite::Error| anyhow!(err));
        let ws_read = ws_read.map_ok(|ws_message| ws_message.into_data()).map_err(|err| anyhow!(err));
        (Box::new(ws_write), Box::new(ws_read))
    }
}

impl WebSock for WebSocket {
    fn ws_split(self) -> (Box<dyn Sink<Vec<u8>, Error=Error> + Unpin + Send>, Box<dyn Stream<Item=Result<Vec<u8>, Error>> + Unpin + Send>) {
        let (ws_write, ws_read) = self.split();
        let ws_write = ws_write.with(|bytes| ready(Ok(warp::ws::Message::binary(bytes)))).sink_map_err(|err: warp::Error| anyhow!(err));
        let ws_read = ws_read.map_ok(|ws_message| ws_message.as_bytes().to_vec()).map_err(|err| anyhow!(err));
        (Box::new(ws_write), Box::new(ws_read))
    }
}