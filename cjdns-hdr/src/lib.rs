//! Library for parsing and serializing cjdns route and data headers. This includes:
//! * [SwitchHeader](struct.SwitchHeader.html) - The header used by the cjdns switch.
//! * [RouteHeader](struct.RouteHeader.html) - This header is emitted from the cjdns engine lower half which tells the upper half where the packet came from, it is also used when sending a packet to/via the lower half, it tells the proper destination and the path which the packet should take (if applicable).
//! * [DataHeader](struct.DataHeader.html) - The data header.
//! * [ContentType](enum.ContentType.html) - Content type enum.
//!
//! When serializing `SwitchHeader` and `DataHeader`, if the version is unspecified, it will be automatically set to the current header version.
//! In `RouteHeader` the version is for telling the core what is the version of the other node: if it is unspecified or zero, the core will attempt to guess it.
//! `SwitchHeader` and `DataHeader` have their own versioning schemes, separate from the overall cjdns version.
//! [SwitchHeader::CURRENT_VERSION](struct.SwitchHeader.html#associatedconstant.CURRENT_VERSION) is the current `SwitchHeader` version and [DataHeader::CURRENT_VERSION](struct.DataHeader.html#associatedconstant.CURRENT_VERSION) is the current `DataHeader` version.
//!
//! # Example
//! ```rust
//! # use hex::decode;
//! use cjdns_hdr::{RouteHeader, SwitchHeader, DataHeader, ContentType};
//! # let hex_to_bytes = |s: &str| -> Vec<u8> { decode(s).expect("invalid hex string") };
//!
//! let data_header_bytes = hex_to_bytes("10000100");
//! let data_header = DataHeader::parse(data_header_bytes.as_slice()).expect("invalid header bytes");
//! assert_eq!(data_header.version, DataHeader::CURRENT_VERSION);
//! assert_eq!(data_header.content_type, ContentType::Cjdht);
//!
//! let switch_header_bytes = hex_to_bytes("000000000000001300480000");
//! let switch_header = SwitchHeader::parse(switch_header_bytes.as_slice()).expect("invalid header bytes");
//! assert_eq!(switch_header.version, SwitchHeader::CURRENT_VERSION);
//! assert_eq!(switch_header.serialize().expect("invalid header"), switch_header_bytes);
//!
//! let route_header_bytes = hex_to_bytes("a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f");
//! let route_header = RouteHeader::parse(route_header_bytes.as_slice()).expect("invalid header bytes");
//! assert_eq!(route_header.switch_header, switch_header);
//! assert!(route_header.is_incoming);
//! assert!(route_header.ip6.is_some());
//! assert_eq!(route_header.serialize().expect("invalid header"), route_header_bytes);
//! ```
//!

pub use cjdns_bytes::{ParseError, SerializeError};
pub use content_type::ContentType;
pub use data_header::DataHeader;
pub use route_header::RouteHeader;
pub use switch_header::SwitchHeader;

mod content_type;
mod data_header;
mod route_header;
mod switch_header;