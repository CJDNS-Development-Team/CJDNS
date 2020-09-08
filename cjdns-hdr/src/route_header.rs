//! Parsing and serialization logic for cjdns header, which is send from the cjdns engine lower half.

use std::convert::TryFrom;

use cjdns_core::keys::{BytesRepr, CJDNSPublicKey, CJDNS_IP6};

use crate::{
    errors::{HeaderError, Result},
    switch_header::SwitchHeader,
    utils::{Reader, Writer},
};

const ROUTE_HEADER_SIZE: usize = 68;
const ZERO_PUBLIC_KEY_BYTES: [u8; 32] = [0; 32];
const ZERO_IP6_BYTES: [u8; 16] = [0; 16];
const INCOMING_FRAME: u8 = 1;
const CONTROL_FRAME: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeader {
    pub public_key: Option<CJDNSPublicKey>,
    pub ip6: Option<CJDNS_IP6>,
    pub version: u32,
    pub switch_header: SwitchHeader,
    pub is_incoming: bool,
    pub is_ctrl: bool,
}

impl RouteHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != ROUTE_HEADER_SIZE {
            return Err(HeaderError::CannotParse("invalid header data size"));
        }
        let mut data_reader = Reader::new(data);
        let public_key = {
            let public_key_array = data_reader.read_array_32().expect("invalid header data size");
            let public_key = if ZERO_PUBLIC_KEY_BYTES == public_key_array {
                None
            } else {
                Some(CJDNSPublicKey::from(public_key_array))
            };
            public_key
        };
        let switch_header = {
            let header_bytes = data_reader.take_bytes(12).expect("invalid header data size");
            SwitchHeader::parse(header_bytes).or(Err(HeaderError::CannotParse("can't parse switch header")))?
        };
        let version = data_reader.read_u32_be().expect("invalid header data size");
        let (is_ctrl, is_incoming) = {
            let flags = data_reader.read_u8().expect("invalid header data size");
            (flags == CONTROL_FRAME, flags == INCOMING_FRAME)
        };
        // pad
        let _unused = data_reader.take_bytes(3).expect("invalid header data size");
        let ip6_from_bytes = {
            let ip6_bytes_slice = data_reader.take_bytes(16).expect("invalid header data size");
            let ip6 = if ip6_bytes_slice == &ZERO_IP6_BYTES {
                None
            } else {
                let from_key = CJDNS_IP6::try_from(ip6_bytes_slice.to_vec()).or(Err(HeaderError::CannotParse("can't create ip6 from bytes")))?;
                Some(from_key)
            };
            ip6
        };
        // checking invariants
        if is_ctrl && public_key.is_some() {
            return Err(HeaderError::CannotParse("public key can not be defined in control frame"));
        }
        if is_ctrl && ip6_from_bytes.is_some() {
            return Err(HeaderError::CannotParse("ip6 is defined for control frame"));
        }
        if !is_ctrl && ip6_from_bytes.is_none() {
            return Err(HeaderError::CannotParse("ip6 is not defined"));
        }
        if public_key.is_some() {
            let ip6_from_key = {
                let ip6_from_key =
                    CJDNS_IP6::try_from(public_key.as_ref().expect("zero key bytes")).or(Err(HeaderError::CannotParse("can't create ip6 from public key")))?;
                Some(ip6_from_key)
            };
            if ip6_from_key != ip6_from_bytes {
                return Err(HeaderError::CannotParse("ip6 derived from public key is not equal to ip6 from header bytes"));
            }
        }
        Ok(RouteHeader {
            public_key,
            ip6: ip6_from_bytes,
            version,
            switch_header,
            is_incoming,
            is_ctrl,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        // checking invariants, because `RouteHeader` can be instantiated without calling constructor
        if !self.is_ctrl && self.ip6.is_none() {
            return Err(HeaderError::CannotSerialize("ip6 is is not defined"));
        }
        if self.is_ctrl && self.ip6.is_some() {
            return Err(HeaderError::CannotSerialize("ip6 is defined for control frame"));
        }
        if self.is_ctrl && self.public_key.is_some() {
            return Err(HeaderError::CannotSerialize("public key can not be defined in control frame"));
        }
        let public_key_bytes = if self.public_key.is_some() {
            self.public_key.as_ref().expect("public key is none").bytes()
        } else {
            ZERO_PUBLIC_KEY_BYTES.into()
        };
        let switch_header_bytes = self.switch_header.serialize()?;
        let flags = if self.is_ctrl { CONTROL_FRAME } else { INCOMING_FRAME };
        let pad_bytes = &[0u8; 3];
        let ip6_bytes = if self.ip6.is_some() {
            self.ip6.as_ref().expect("ip6 is none").bytes()
        } else {
            ZERO_IP6_BYTES.into()
        };

        let mut data_writer = Writer::with_capacity(ROUTE_HEADER_SIZE);
        // TODO ask Alex if to follow wrote style in switch and data headers
        let data = &[
            public_key_bytes.as_slice(),
            switch_header_bytes.as_slice(),
            &self.version.to_be_bytes(),
            &[flags],
            pad_bytes,
            ip6_bytes.as_slice(),
        ]
        .concat();
        data_writer.write_slice(data);
        Ok(data_writer.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use cjdns_core::{
        keys::{CJDNSPublicKey, CJDNS_IP6},
        RoutingLabel,
    };

    use super::RouteHeader;
    use crate::switch_header::SwitchHeader;

    #[test]
    fn test_route_header_parse() {
        let test_data = hex::decode(
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f",
        )
        .expect("invalid hex string");
        let parsed_header = RouteHeader::parse(&test_data).expect("invalid header bytes");
        assert_eq!(
            parsed_header,
            RouteHeader {
                public_key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).ok(),
                ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).ok(),
                version: 0,
                switch_header: SwitchHeader {
                    label: RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
                    congestion: 0,
                    suppress_errors: false,
                    version: 1,
                    label_shift: 8,
                    penalty: 0,
                },
                is_incoming: true,
                is_ctrl: false,
            }
        );
    }

    #[test]
    fn test_route_header_serialize() {
        let route_header = RouteHeader {
            public_key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).ok(),
            ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).ok(),
            version: 0,
            switch_header: SwitchHeader {
                label: RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
                congestion: 0,
                suppress_errors: false,
                version: 1,
                label_shift: 8,
                penalty: 0,
            },
            is_incoming: true,
            is_ctrl: false,
        };
        let header_bytes = hex::decode(
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f",
        )
        .expect("invalid hex string");
        let serialized_header = route_header.serialize().expect("invalid header");
        assert_eq!(header_bytes, serialized_header);
    }
}
