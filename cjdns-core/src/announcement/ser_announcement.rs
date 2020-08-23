use crate::{Announcement, AnnouncementHeader, AnnouncementEntities, Entities};

pub use self::ser_data::*;
use self::parser::*;
use self::errors::*;

const MIN_SIZE: usize = HEADER_SIZE;
const HEADER_SIZE: usize = SIGN_SIZE + SIGN_KEY_SIZE + IP_SIZE + 8;
const SIGN_SIZE: usize = 64_usize;
const SIGN_KEY_SIZE: usize = 32_usize;
const IP_SIZE: usize = 16_usize;

mod ser_data {
    use std::convert::TryFrom;

    use sodiumoxide::crypto::hash::sha512::{hash, Digest};
    use sodiumoxide::crypto::sign::ed25519::{verify_detached, Signature, PublicKey};

    use super::*;

    type Result<T> = std::result::Result<T, PacketError>;

    #[derive(Debug, Clone)]
    pub struct AnnouncementPacket(Vec<u8>);

    impl AnnouncementPacket {

        /// Instantiates wrapper on announcement message
        pub fn try_new(ann_data: Vec<u8>) -> Result<Self> {
            if ann_data.len() < MIN_SIZE {
                return Err(PacketError::CannotInstantiatePacket);
            }
            Ok(Self(ann_data))
        }

        /// Checks announcement message signature validity
        pub fn check(&self) -> Result<()>{
            let signature = Signature::from_slice(self.get_signature_bytes()).expect("input slice size ne to 64");
            let public_sign_key = PublicKey::from_slice(self.get_pub_key_bytes()).expect("input slice size ne to 32");
            let signed_data = self.signed_data();
            if verify_detached(&signature, signed_data, &public_sign_key) {
                return Ok(());
            }
            Err(PacketError::InvalidPacketSignature)
        }

        /// Parses announcement packet and creates `Announcement` struct
        pub fn parse(self) -> Announcement {
            parse(self)?
        }

        /// Gets packet hash
        pub fn get_hash(&self) -> Digest {
            hash(&self.0)
        }

        pub fn get_entities_bytes(&self) -> &[u8] {
            &self.0[HEADER_SIZE..]
        }

        pub fn get_header_bytes(&self) -> &[u8] {
            &self.0[..HEADER_SIZE]
        }

        fn get_signature_bytes(&self) -> &[u8] {
            &self.0[..SIGN_SIZE]
        }

        fn get_pub_key_bytes(&self) -> &[u8] {
            &self.get_signed_data()[..SIGN_KEY_SIZE]
        }

        fn get_signed_data(&self) -> &[u8] {
            &self.0[SIGN_SIZE..]
        }
    }
}

mod parser {
    use std::convert::TryFrom;

    use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;
    use sodiumoxide::crypto::sign::ed25519::PublicKey;

    use crate::keys::{CJDNSPublicKey, CJDNS_IP6};

    use super::*;

    type Result<T> = std::result::Result<T, ParserError>;

    const ENCODING_SCHEME_TYPE: u8 = 0u8;
    const PEER_TYPE: u8 = 1u8;
    const VERSION_TYPE: u8 = 2u8;

    // Dividing logic from DS (`AnnouncementPacket`)
    pub fn parse(packet: AnnouncementPacket) -> Result<Announcement> {
        let header = parse_header(packet.get_header_bytes())?;
        let (node_encryption_key, node_ip6) = parse_sender_auth_data(header.pub_signing_key.as_bytes())?;
        let entities = parse_entities(packet.get_entities_bytes())?;
    }

    fn parse_header(header_data: &[u8]) -> Result<AnnouncementHeader> {
        let (signature_data, header_without_sign) = header_data.split_at(SIGN_SIZE);
        let signature = hex::encode(signature_data);

        let (signing_key_data, header_without_sign_n_key) = header_without_sign.split_at(SIGN_KEY_SIZE);
        let pub_signing_key = hex::encode(signing_key_data);

        let (super_node_data, rest_header) = header_without_sign_n_key.split_at(IP_SIZE);
        let super_node_ip = CJDNS_IP6::try_from(super_node_data.to_vec()).or(Err(ParserError::CannotParseHeader("failed ip6 creation from bytes data")))?; // todo actually it's ugly

        assert_eq!(rest_header.len(), 8, "Header size is gt 120 bytes");
        let last_byte = rest_header[7];
        let version = {
            // version is encoded as a number from last 3 bits
            // For example:
            // last byte is NNNN_NNNN, where N is either 0 or 1
            // so version is 0000_0NNN = NNNN_NNNN & 111
            last_byte & 7
        };
        let is_reset = {
            // this flag is encoded in the fourth byte from the right
            // For example:
            // last byte is AAAA_AAAA, where N is either 0 or 1
            // so reset flag is the bit N in last byte: AAAA_NAAA
            (last_byte >> 3) & 1 == 1
        };

        // TODO is this `rest_msg[7] &= 0xf0` really necessary, if we shift timestamp to right?
        let mut timestamp = u64::from_be_bytes(<[u8; 8]>::try_from(rest_header).expect("slice array size is ne to 8"));
        timestamp >>= 4;

        Ok(AnnouncementHeader {
            signature,
            pub_signing_key,
            super_node_ip,
            version,
            is_reset,
            timestamp,
        })
    }

    fn parse_sender_auth_data(sender_auth_data: &[u8]) -> Result<(CJDNSPublicKey, CJDNS_IP6)> {
        // auth encryption key
        let mut curve25519_key_bytes = [0u8; SIGN_KEY_SIZE];
        // ed25519 key
        let public_sign_key = PublicKey::from_slice(sender_auth_data).expect("sender sign key size is gt 32");
        let ok = unsafe { crypto_sign_ed25519_pk_to_curve25519(curve25519_key_bytes.as_mut_ptr(), public_sign_key.0.as_ptr()) == 0 };
        if !ok {
            return Err(ParserError::CannotParseAuthData("Convertion from x25519 to curve25519 failed"));
        }
        let node_encryption_key = CJDNSPublicKey::from(curve25519_key_bytes);
        let node_ip6 = CJDNS_IP6::try_from(&node_encryption_key).or(Err(ParserError::CannotParseAuthData("failed ip6 creation from auth pub key")))?;
        Ok((node_encryption_key, node_ip6))
    }

    fn parse_entities(entities_data: &[u8]) -> Result<AnnouncementEntities> {

    }
}

mod errors {

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub(super) enum PacketError {
        CannotInstantiatePacket,
        InvalidPacketSignature,
    }

    impl std::fmt::Display for PacketError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                PacketError::CannotInstantiatePacket => write!(f, "Can't instantiate AnnouncementPacket instance from providing data"),
                PacketError::InvalidPacketSignature => write!(f, "Announcement packet has invalid signature on packet data"),
            }
        }
    }

    impl std::error::Error for PacketError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub(super) enum ParserError {
        CannotParseHeader(&'static str),
        CannotParseAuthData(&'static str)
    }

    impl std::fmt::Display for ParserError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                ParserError::CannotParseHeader(fail_reason) => write!(f, "Can't create IP6 {}", fail_reason),
                ParserError::CannotParseAuthData(fail_reason) => write!(f, "Failed sender auth data parse {}", fail_reason)
            }
        }
    }

    impl std::error::Error for ParserError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }
}