//! Library for parsing and serializing cjdns route and data headers. This includes:
//! * [SwitchHeader]() - The header used by the cjdns switch.
//! * [RouteHeader]() - This header is emitted from the cjdns engine lower half which tells the upper half where the packet came from, it is also used when sending a packet to/via the lower half, it tells the proper destination and the path which the packet should take (if applicable).
//! * [DataHeader]() - This is a simple header which merely tells the type of content.
//! * [ContentType]() - This is an enum of content types.
//!
//! When serializing `SwitchHeader` and `DataHeader`, if the version is unspecified, it will be automatically set to the current header version.
//! In `RouteHeader` the version is for telling the core what is the version of the other node: if it is unspecified or zero, the core will attempt to guess it.
//! `SwitchHeader` and `DataHeader` have their own versioning schemes, separate from the overall cjdns version.
//! [SwitchHeader::CURRENT_VERSION]() is the current `SwitchHeader` version and [DataHeader::CURRENT_VERSION]() is the current `DataHeader` version.
//!
//! # Example
//!
//! TODO

pub use data_header::{DataHeader, ContentType};
pub use route_header::RouteHeader;
pub use switch_header::SwitchHeader;

mod data_header;
mod errors;
mod route_header;
mod switch_header;
mod utils;
