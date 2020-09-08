//! Parsing and serialization logic for cjdns header, which is send from the cjdns engine lower half.

use cjdns_core::keys::{CJDNSPublicKey, CJDNS_IP6};

use crate::{
    errors::{HeaderError, Result},
    utils::{Reader, Writer},
    switch_header::SwitchHeader
};


const ROUTE_HEADER_SIZE: usize = 68;
const HEADER_CURRENT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeader {
    pub public_key: CJDNSPublicKey,
    pub ip6: CJDNS_IP6,
    pub version: u8,
    pub switch_header: SwitchHeader,
}

impl RouteHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
    }
}

#[cfg(test)]
mod tests {
}
