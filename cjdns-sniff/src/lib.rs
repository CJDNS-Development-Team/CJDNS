//! Library for sniffing and injecting cjdns traffic.
//!
//! **NOTE**: This requires cjdns v18 or higher.

use std::io;

use thiserror::Error;
use tokio::net::UdpSocket;

use cjdns_admin::{cjdns_invoke, ReturnValue};
pub use cjdns_admin::Connection;
use cjdns_bytes::{ParseError, SerializeError};
use cjdns_hdr::{DataHeader, RouteHeader};
pub use cjdns_hdr::ContentType;

pub struct Sniffer {
    cjdns: Connection,
    socket: UdpSocket,
}

#[derive(Clone, Default, Debug)]
pub struct Message {
    pub route_header: Option<RouteHeader>,
    pub data_header: Option<DataHeader>,
    pub content_bytes: Option<Vec<u8>>,
    pub raw_bytes: Option<Vec<u8>>,
    pub content_benc: Option<()>, //TODO need proper type here - bencode module
    pub content: Option<()>, //TODO need proper type here - cjdns-ctrl
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

    pub async fn send(&mut self, msg: Message, dest: Option<&str>) -> Result<(), SendError> {
        let dest = dest.unwrap_or("fc00::1");

        let mut buf = Vec::new();

        if let Some(ref route_header) = msg.route_header {
            let route_header_bytes = route_header.serialize().map_err(|e| SendError::SerializeError(e))?;
            buf.extend_from_slice(&route_header_bytes);
        }

        if let Some(ref data_header) = msg.data_header {
            let data_header_bytes = data_header.serialize().map_err(|e| SendError::SerializeError(e))?;
            buf.extend_from_slice(&data_header_bytes);
        }

        let content_bytes = match &msg {
            Message { data_header: Some(data_header), content_benc: Some(_content_benc), .. } if data_header.content_type == ContentType::Cjdht => {
                /* Bencode.encode(content_benc) */ None //TODO implement when Bencode module is refactored
            }
            Message { route_header: Some(route_header), content: Some(_content), .. } if route_header.is_ctrl => {
                /* Cjdnsctrl.serialize(msg.content) */ None //TODO implement when cjdns-ctrl is ready
            }
            Message { content_bytes: Some(content_bytes), .. } => {
                Some(content_bytes)
            }
            _ => None,
        };

        if let Some(content_bytes) = content_bytes {
            buf.extend_from_slice(content_bytes);
        }

        let written = self.socket.send_to(&buf, dest).await.map_err(|e| SendError::SocketError(e))?;
        if written != buf.len() {
            return Err(SendError::WriteError(written, buf.len()));
        }

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Message, ReceiveError> {
        // Limit receive packet lenght to typical Ethernet MTU for now; need to check actual max packet length on CJDNS Node side though.
        let mut buf = [0; 1500];

        let (size, _) = self.socket.recv_from(&mut buf).await.map_err(|e| ReceiveError::SocketError(e))?;
        let data = &buf[..size];
        let msg = Self::decode_message(data).map_err(|e| ReceiveError::ParseError(e))?;

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

    fn decode_message(bytes: &[u8]) -> Result<Message, ParseError> {
        // Check total length
        if bytes.len() < RouteHeader::SIZE {
            return Err(ParseError::InvalidPacketSize);
        }

        // Whole packet
        let raw_bytes = Vec::from(bytes);

        // Route header
        let route_header_bytes = &bytes[0..RouteHeader::SIZE];
        let bytes = &bytes[RouteHeader::SIZE..];
        let route_header = RouteHeader::parse(route_header_bytes)?;
        let is_ctrl = route_header.is_ctrl;

        // Data header
        if !is_ctrl && bytes.len() < DataHeader::SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let data_header_bytes = if is_ctrl { None } else { Some(&bytes[0..DataHeader::SIZE]) };
        let bytes = if is_ctrl { bytes } else { &bytes[DataHeader::SIZE..] };
        let data_header = if let Some(data_header_bytes) = data_header_bytes {
            Some(DataHeader::parse(data_header_bytes)?)
        } else {
            None
        };

        // Data itself
        let data_bytes = if bytes.len() > 0 { Some(bytes) } else { None };

        // Bencoded content
        let content_benc = match &data_header {
            Some(data_header) if data_header.content_type == ContentType::Cjdht => {
                /* out.contentBenc = Bencode.decode(dataBytes); */ //TODO implement this when Bencode module is propely refactored
                Some(())
            }
            _ => None
        };

        // Control message content
        let content = if content_benc.is_none() && is_ctrl {
            /* -- TODO fix this when cjdns-ctrl is available
            try {
                out.content = Cjdnsctrl.parse(dataBytes);
            } catch (e) {
                out.content = {
                    error: e.message
                };
            }
            */
            Some(())
        } else {
            None
        };

        // Resulting message
        let msg = Message {
            route_header: Some(route_header),
            data_header,
            content_bytes: data_bytes.map(Vec::from),
            raw_bytes: Some(raw_bytes),
            content_benc,
            content,
        };

        Ok(msg)
    }
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("Failed to communicate with CJDNS router: {0}")]
    RpcError(#[source] cjdns_admin::Error),

    #[error("Failed to communicate with CJDNS router: bad RPC response")]
    BadResponse,

    #[error("Failed to connect to CJDNS router: {0}")]
    SocketError(#[source] io::Error),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("Data serialization error: {0}")]
    SerializeError(#[source] SerializeError),

    #[error("Failed to connect to CJDNS router: {0}")]
    SocketError(#[source] io::Error),

    #[error("Failed to send buffer: only {0} of {1} bytes written")]
    WriteError(usize, usize),
}

#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error("Failed to connect to CJDNS router: {0}")]
    SocketError(#[source] io::Error),

    #[error("Data parse error: {0}")]
    ParseError(#[source] ParseError),
}