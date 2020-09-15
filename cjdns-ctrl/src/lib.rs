//! Parsing/serializing CTRL messages
//!
//! Cjdns contains a set of low level messages which are not encrypted. If you send a packet and it cannot be forwarded, the switch,
//! which knows it is not possible to forward, will notify you with a CTRL message, these are not encrypted
//! because, obviously, the switch doesn't know who you are and can't reasonably encrypt anything to you.
//!
//! # CTRL message types
//! * PING: request that the content of the message be echoed back to you
//! * PONG: response to a PING message
//! * KEYPING: Similar to a ping except that the message also sends a public key and requests one back.
//! *NOTE*: When constructing a keyping, remember that the key you send is your key and the other person's key should be in the response.
//! * KEYPONG: Response to a KEYPING message, contains the responder's key.
//! * ERROR: Emitted by the switch in case a message cannot be forwarded.
//!
//! # Error message types
//! * MALFORMED_ADDRESS: The switch label was malformed
//! * FLOOD: Packet dropped because link is congested (never sent as of v18)
//! * LINK_LIMIT_EXCEEDED: Packet dropped because node has oversent its limit (never sent as of v18)
//! * OVERSIZE_MESSAGE: Message too big to send, caused by differing MTU along a path
//! * UNDERSIZED_MESSAGE: Message smaller than expected headers
//! * AUTHENTICATION: Authentication failed (CryptoAuth could not understand the packet)
//! * INVALID: Header is invalid or checksum failed
//! * UNDELIVERABLE: Message could not be sent to its destination through no fault of the sender
//! * LOOP_ROUTE: The route enters and leaves through the same interface in one switch
//! * RETURN_PATH_INVALID: The switch is unable to represent the return path, this basically means that
//! the label is so long that the inverse label is impossible to put in 64 bits.
//!
//! # Example
//! ```rust
//! # use std::convert::TryFrom;
//! # use hex::decode;
//! # use cjdns_core::keys::CJDNSPublicKey;
//! use cjdns_ctrl::*;
//! # let hex_to_bytes = |s: &str| -> Vec<u8> { decode(s).expect("invalid hex string") };
//!
//! let test_bytes = hex_to_bytes("994b00050123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3");
//! let test_message_inst = CtrlMessage {
//!     msg_type: CtrlMessageType::KeyPing,
//!     msg_data: CtrlMessageData::PingData(PingData {
//!         version: 18,
//!         key: Some(
//!             CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).expect("invalid key string")
//!         ),
//!         content: hex_to_bytes("02e29842b42aedb6bce2ead3"),
//!     }),
//! };
//!
//! let parsed_msg = CtrlMessage::parse(&test_bytes).expect("invalid message bytes");
//! let serialized_msg = parsed_msg.serialize().expect("invalid message instance");
//! assert_eq!(parsed_msg, test_message_inst);
//! assert_eq!(serialized_msg, test_bytes)
//! ```

pub use ping_data::PingData;
pub use control_message::{CtrlMessage, CtrlMessageType, CtrlMessageData};
pub use error_data::{ErrorData, ErrorMessageType};

mod ping_data;
mod control_message;
mod error_data;
