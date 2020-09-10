//! Library for sniffing and injecting cjdns traffic.
//!
//! **NOTE**: This requires cjdns v18 or higher.

use std::io;

use thiserror::Error;
use tokio::net::UdpSocket;

use cjdns_admin::{cjdns_invoke, ReturnValue};
pub use cjdns_admin::Connection;

//TODO This is a temporary type, until cjdns-hdr is fully available
pub enum ContentType {
    CJDHT = 256,
    CTRL = 0xffff + 1,
}

pub struct Sniffer {
    cjdns: Connection,
    socket: UdpSocket,
}

//TODO need cjdns-hdr & cjdns-ctrl
#[derive(Debug)]
pub struct Message<'a> {
    pub data_header: Option<()>,
    pub content_benc: Option<()>,
    pub route_header: Option<()>,
    pub content: Option<()>,
    pub content_bytes: Option<&'a [u8]>,
}

impl Sniffer {
    pub async fn sniff_traffic(mut conn: Connection, content_type: ContentType) -> Result<Self, ConnectError> {
        let udp_socket = Self::connect(&mut conn, content_type).await?;
        let res = Sniffer {
            cjdns: conn,
            socket: udp_socket,
        };
        Ok(res)
    }

    async fn connect(conn: &mut Connection, content_type: ContentType) -> Result<UdpSocket, ConnectError> {
        let content_type_code = content_type as u32;
        if let Some(udp_socket) = Self::connect_with_existing_port(conn, content_type_code).await? {
            return Ok(udp_socket);
        }
        let udp_socket = Self::connect_with_new_port(conn, content_type_code).await?;
        Ok(udp_socket)
    }

    async fn connect_with_existing_port(conn: &mut Connection, content_type_code: u32) -> Result<Option<UdpSocket>, ConnectError> {
        // Request list of handlers
        for page in 0.. {
            let res = cjdns_invoke!(conn, "UpperDistributor_listHandlers", "page" = page).await.map_err(|e| ConnectError::RpcError(e))?;
            // Expected response is of form `{ "handlers" : [ { "type" : 0xFFF1, "udpPort" : 1234 }, { "type" : 0xFFF2, "udpPort" : 1235 }, ... ] }`
            let handlers = res
                .get("handlers").ok_or(ConnectError::BadResponse)?
                .as_list(ReturnValue::as_int_map).map_err(|_| ConnectError::BadResponse)?
            ;

            if handlers.is_empty() { // Last page has empty handlers list
                break;
            }

            // Process handlers
            for handler in handlers {
                if let (Some(&handler_content_type), Some(&handler_udp_port)) = (handler.get("type"), handler.get("udpPort")) {
                    if handler_content_type < 0 || handler_content_type > u32::MAX as i64 || handler_udp_port <= 0 || handler_udp_port > u16::MAX as i64 {
                        return Err(ConnectError::BadResponse);
                    }
                    let (handler_content_type, handler_udp_port) = (handler_content_type as u32, handler_udp_port as u16);
                    if handler_content_type != content_type_code {
                        continue;
                    }
                    let addr = format!(":::{}", handler_udp_port);
                    match UdpSocket::bind(addr).await {
                        Ok(socket) => return Ok(Some(socket)),
                        Err(err) if err.kind() == io::ErrorKind::AddrInUse => { /* Ignore this error, just use another port later */ },
                        Err(err) => return Err(ConnectError::SocketError(err)),
                    }
                } else {
                    return Err(ConnectError::BadResponse);
                }
            }
        }

        Ok(None)
    }

    async fn connect_with_new_port(conn: &mut Connection, content_type_code: u32) -> Result<UdpSocket, ConnectError> {
        // Bind a new UDP socket on random port
        let socket = UdpSocket::bind(":::0").await.map_err(|e| ConnectError::SocketError(e))?;
        let port = socket.local_addr().map_err(|e| ConnectError::SocketError(e))?.port();

        // Register this port within CJDNS router
        cjdns_invoke!(conn, "UpperDistributor_registerHandler", "contentType" = content_type_code as i64, "udpPort" = port as i64).await.map_err(|e| ConnectError::RpcError(e))?;

        Ok(socket)
    }

    #[allow(unused_variables, unused_mut)]//todo REMOVE when done
    pub async fn send(&mut self, msg: Message<'_>, dest: Option<&str>) -> Result<(), SendError> {
        let dest = dest.unwrap_or("fc00::1");

        let mut buf = Vec::new();

        if let Some(route_header) = msg.route_header {
            let route_header_bytes = /* Cjdnshdr.RouteHeader.serialize(msg.routeHeader) */(); //TODO
            //buf.extend_from_slice(route_header_bytes); //TODO
        }

        if let Some(data_header) = msg.data_header {
            let data_header_bytes = /* Cjdnshdr.DataHeader.serialize(msg.dataHeader) */(); //TODO
            //buf.extend_from_slice(data_header_bytes); //TODO
        }

        let content_bytes = match msg {
            Message { data_header: Some(data_header), content_benc: Some(content_benc), .. } /*if data_header.content_type == ContentType::CJDHT*/ => { //TODO
                /* Bencode.encode(content_benc) */ () //TODO
            }
            Message { route_header: Some(route_header), content: Some(content), .. } /*if route_header.is_ctrl*/ => { //TODO
                /* Cjdnsctrl.serialize(msg.content) */ () //TODO
            }
            Message { content_bytes: Some(content_bytes), .. } => {
                /* content_bytes */ () //TODO
            }
            _ => return Err(SendError::BadMessage),
        };

        //buf.extend_from_slice(content_bytes); //TODO

        if buf.is_empty() {
            return Err(SendError::BadMessage);
        }

        let written = self.socket.send_to(&buf, dest).await.map_err(|e| SendError::SocketError(e))?;
        if written != buf.len() {
            return Err(SendError::WriteError(written, buf.len()));
        }

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Event, ReceiveError> {
        // Limit receive packet lenght to typical Ethernet MTU for now; need to check actual max packet length on CJDNS Node side though.
        let mut buf = [0; 1500];

        let (size, _) = self.socket.recv_from(&mut buf).await.map_err(|e| ReceiveError::SocketError(e))?;
        let data = &buf[..size];
        let msg = Self::decode_message(data).ok_or(ReceiveError::BadMessage)?;

        Ok(msg)
    }

    pub async fn disconnect(&mut self) -> Result<(), ConnectError> {
        // Get local UDP port we are listening on
        let port = self.socket.local_addr().map_err(|e| ConnectError::SocketError(e))?.port();

        // Unregister this handler from CJDNS router
        let conn = &mut self.cjdns;
        cjdns_invoke!(conn, "UpperDistributor_unregisterHandler", "udpPort" = port as i64).await.map_err(|e| ConnectError::RpcError(e))?;

        // UDP socket will be disconnected automatically when dropped
        Ok(())
    }

    //TODO implement properly when cjdns-hdr is available
    fn decode_message(bytes: &[u8]) -> Option<Event> {
        const ROUTE_HEADER_SIZE: usize = 68;
        const DATA_HEADER_SIZE: usize = 4;

        if bytes.len() < ROUTE_HEADER_SIZE {
            return None;
        }

        let route_header_bytes = &bytes[0..ROUTE_HEADER_SIZE];
        let bytes = &bytes[ROUTE_HEADER_SIZE..];
        //TODO parse route header
        let is_ctrl = (route_header_bytes[48] & (1 << 1)) != 0;

        if !is_ctrl && bytes.len() < DATA_HEADER_SIZE {
            return None;
        }

        let data_header_bytes = if is_ctrl { None } else { Some(&bytes[0..DATA_HEADER_SIZE]) };
        let bytes = if is_ctrl { bytes } else { &bytes[DATA_HEADER_SIZE..] };
        //TODO parse optional data header

        let data_bytes = bytes;

        Some(Event(Vec::from(route_header_bytes), data_header_bytes.map(|b| Vec::from(b)), Vec::from(data_bytes)))
    }
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("Failed to communicate with CJDNS router: {0}")]
    RpcError(cjdns_admin::Error),

    #[error("Failed to communicate with CJDNS router: bad RPC response")]
    BadResponse,

    #[error("Failed to connect to CJDNS router: {0}")]
    SocketError(io::Error),

    #[error("Bad message")]
    BadMessage,
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("Bad message")]
    BadMessage,

    #[error("Failed to connect to CJDNS router: {0}")]
    SocketError(io::Error),

    #[error("Failed to send buffer: only {0} of {1} bytes written")]
    WriteError(usize, usize),
}

#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error("Failed to connect to CJDNS router: {0}")]
    SocketError(io::Error),

    #[error("Bad message")]
    BadMessage,
}

//TODO this is a temporary type until cjdns-hdr is available
#[derive(Debug)]
pub struct Event(pub Vec<u8>, pub Option<Vec<u8>>, pub Vec<u8>);