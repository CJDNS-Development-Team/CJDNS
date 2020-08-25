use std::convert::TryFrom;

use sodiumoxide::crypto::hash::sha512::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{verify_detached, PublicKey, Signature};

use crate::{
    deserialize_forms,
    keys::{CJDNSPublicKey, CJDNS_IP6},
    announcement::errors::*,
    DefaultRoutingLabel, EncodingSchemeForm,
    Announcement, AnnouncementHeader, AnnouncementEntities, Entity,
};

const MIN_SIZE: usize = HEADER_SIZE;
const HEADER_SIZE: usize = SIGN_SIZE + SIGN_KEY_SIZE + IP_SIZE + 8;
const SIGN_SIZE: usize = 64_usize;
const SIGN_KEY_SIZE: usize = 32_usize;
const IP_SIZE: usize = 16_usize;

pub mod serialized_data {

    use super::*;

    type Result<T> = std::result::Result<T, PacketError>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AnnouncementPacket(pub Vec<u8>); // TODO WAT

    impl AnnouncementPacket {
        /// Instantiates wrapper on announcement message
        pub fn try_new(ann_data: Vec<u8>) -> Result<Self> {
            if ann_data.len() < MIN_SIZE {
                return Err(PacketError::CannotInstantiatePacket);
            }
            Ok(Self(ann_data))
        }

        /// Checks announcement message signature validity
        pub fn check(&self) -> Result<()> {
            let signature = Signature::from_slice(self.get_signature_bytes()).expect("input slice size ne to 64");
            let public_sign_key = PublicKey::from_slice(self.get_pub_key_bytes()).expect("input slice size ne to 32");
            let signed_data = self.get_signed_data();
            if verify_detached(&signature, signed_data, &public_sign_key) {
                return Ok(());
            }
            Err(PacketError::InvalidPacketSignature)
        }

        /// Parses announcement packet and creates `Announcement` struct
        pub fn parse(self) -> Result<Announcement> {
            parser::parse(self).map_err(|e| PacketError::CannotParsePacket(e))
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

        pub(super) fn get_pub_key_bytes(&self) -> &[u8] {
            &self.get_signed_data()[..SIGN_KEY_SIZE]
        }

        fn get_signed_data(&self) -> &[u8] {
            &self.0[SIGN_SIZE..]
        }
    }
}

mod parser {

    use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;

    use super::*;

    type Result<T> = std::result::Result<T, ParserError>;

    const PEER_TYPE: u8 = 1_u8;
    const VERSION_TYPE: u8 = 2_u8;
    const ENCODING_SCHEME_TYPE: u8 = 0_u8;
    const PEER_ENTITY_SIZE: usize = 32_usize;
    const VERSION_ENTITY_SIZE: usize = 4_usize;
    const ENCODING_SCHEME_ENTITY_MIN_SIZE: usize = 2_usize;

    // Dividing logic from DS (`AnnouncementPacket`)
    pub fn parse(packet: serialized_data::AnnouncementPacket) -> Result<Announcement> {
        let header = parse_header(packet.get_header_bytes())?;
        let (node_encryption_key, node_ip6) = parse_sender_auth_data(packet.get_pub_key_bytes())?;
        let entities = parse_entities(packet.get_entities_bytes())?;
        let binary_hash = packet.get_hash();
        Ok(Announcement {
            header,
            node_encryption_key,
            node_ip6,
            entities,
            binary_hash,
            binary: packet,
        })
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
        let mut parsed_entities = Vec::new();
        let mut idx = 0_usize;
        while idx < entities_data.len() {
            let entity_len = entities_data[idx] as usize;
            let entity_type = entities_data[idx + 1];
            let entity_data = &entities_data[idx..idx + entity_len];

            if entity_len == 0 || entity_len != entity_data.len() {
                return Err(ParserError::CannotParseEntity("Invalid entity length in message"));
            }
            if entity_len == 1 {
                idx += 1;
                continue;
            }

            let parsed_entity = parse_entity(entity_type, entity_data)?; // TODO `None` is unrecognized staff. What shall we do with it? Better ok_or(Err(unrecognized entity))
            if let Some(entity) = parsed_entity {
                parsed_entities.push(entity)
            }

            idx += entities_data[idx] as usize;
        }
        // TODO how to reach this?
        if idx != entities_data.len() {
            return Err(ParserError::CannotParseEntity("garbage after the last announcement entity"));
        }
        Ok(AnnouncementEntities(parsed_entities))
    }

    fn parse_entity(entity_type: u8, entity_data: &[u8]) -> Result<Option<Entity>> {
        // First byte of each entity data is its length. The second byte is its type. So "non meta" data of each entity starts from index 2 (3d byte).
        let parsing_data = &entity_data[2_usize..];
        match entity_type {
            ENCODING_SCHEME_TYPE => {
                if entity_data.len() < ENCODING_SCHEME_ENTITY_MIN_SIZE {
                    return Err(ParserError::CannotParseEntity("invalid encoding scheme data size"));
                }
                let scheme_entity = parse_encoding_scheme(parsing_data)?;
                Ok(Some(scheme_entity))
            }
            PEER_TYPE => {
                if entity_data.len() != PEER_ENTITY_SIZE {
                    return Err(ParserError::CannotParseEntity("invalid peer data size"));
                }
                let peer_entity = parse_peer(parsing_data)?;
                Ok(Some(peer_entity))
            }
            VERSION_TYPE => {
                if entity_data.len() != VERSION_ENTITY_SIZE {
                    return Err(ParserError::CannotParseEntity("invalid version data size"));
                }
                let version_entity = parse_version(parsing_data)?;
                Ok(Some(version_entity))
            }
            _ => Ok(None),
        }
    }

    fn parse_encoding_scheme(encoding_scheme_data: &[u8]) -> Result<Entity> {
        let hex = hex::encode(encoding_scheme_data);
        let scheme = deserialize_forms(encoding_scheme_data).or(Err(ParserError::CannotParseEntity("encoding scheme deserialization failed")))?;
        Ok(Entity::EncodingScheme { hex, scheme })
    }

    fn parse_version(version_data: &[u8]) -> Result<Entity> {
        assert_eq!(version_data.len(), 2);
        let version = u16::from_be_bytes(<[u8; 2]>::try_from(version_data).expect("version slice is ne to 2"));
        Ok(Entity::Version(version))
    }

    fn parse_peer(peer_data: &[u8]) -> Result<Entity> {
        assert_eq!(peer_data.len(), 30);
        let mut peer_data_iter = peer_data.iter();
        let mut take_from_data_to_vec = |n: usize| peer_data_iter.by_ref().take(n).map(|&byte| byte).collect::<Vec<u8>>();
        let (encoding_form_number, flags) = {
            let e_f = take_from_data_to_vec(2);
            let err_msg = "peer data is empty";
            let (&encoding_form_number, &flags) = (e_f.first().expect(err_msg), e_f.last().expect(err_msg));
            (encoding_form_number, flags)
        };
        let mtu = {
            let mtu8 = u16::from_be_bytes(<[u8; 2]>::try_from(take_from_data_to_vec(2).as_slice()).expect("mtu bytes slice size is ne to 2"));
            mtu8 as u32 * 8
        };
        let peer_num = u16::from_be_bytes(<[u8; 2]>::try_from(take_from_data_to_vec(2).as_slice()).expect("peer_num slice size is ne to 2"));
        let unused = u32::from_be_bytes(<[u8; 4]>::try_from(take_from_data_to_vec(4).as_slice()).expect("unused slice size is ne to 4"));
        let ipv6 = CJDNS_IP6::try_from(take_from_data_to_vec(16)).or(Err(ParserError::CannotParseEntity("failed ip6 creation from entity bytes")))?;
        // TODO RoutingLabel<u32>?
        let label = {
            let label_bytes_hexed = take_from_data_to_vec(4)
                .chunks(2)
                .map(|two_bytes| hex::encode(two_bytes))
                .collect::<Vec<String>>()
                .join(".");
            let label_string = format!("{}{}", "0000.0000.", label_bytes_hexed);
            DefaultRoutingLabel::try_from(label_string.as_str())
                .or(Err(ParserError::CannotParseEntity("routing label creation from peer entity bytes failed")))?
        };
        Ok(Entity::Peer {
            ipv6,
            label,
            mtu,
            peer_num,
            unused,
            encoding_form_number,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {

    use std::convert::TryFrom;

    use sodiumoxide::crypto::hash::sha512::hash;

    use super::*;

    #[test]
    fn test_general() {
        let hexed_header = String::from("3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2fc928136dc1fe6e04ef6a6dd7187b85f00001576462f6f69");
        let hexed_version_entity = String::from("04020012");
        let hexed_pad = String::from("01");
        let hexed_enc_entity = String::from("07006114458100");
        let hexed_peer_entity = String::from("200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015");
        let test_data = format!("{}{}{}{}{}", hexed_header, hexed_version_entity, hexed_pad, hexed_enc_entity, hexed_peer_entity);
        let test_bytes = hex::decode(test_data).expect("test bytes from https://github.com/cjdelisle/cjdnsann/blob/master/test.js#L30");
        let test_bytes_hash = hash(&test_bytes);
        let a = serialized_data::AnnouncementPacket::try_new(test_bytes.clone()).unwrap();
        let res = a.parse();
        assert_eq!(
            res.unwrap(),
            Announcement {
                header: AnnouncementHeader {
                    signature:
                    "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09"
                        .to_string(),
                    pub_signing_key: "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2".to_string(),
                    super_node_ip: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("cjdns base test example failed"),
                    version: 1,
                    is_reset: true,
                    timestamp: 1474857989878
                },
                entities: AnnouncementEntities(vec![
                    Entity::Version(18),
                    Entity::EncodingScheme {
                        hex: "6114458100".to_string(),
                        scheme: vec![
                            EncodingSchemeForm {
                                bit_count: 3,
                                prefix_len: 1,
                                prefix: 1
                            },
                            EncodingSchemeForm {
                                bit_count: 5,
                                prefix_len: 2,
                                prefix: 2
                            },
                            EncodingSchemeForm {
                                bit_count: 8,
                                prefix_len: 2,
                                prefix: 0
                            },
                        ]
                    },
                    Entity::Peer {
                        ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("cjdns base test example failed"),
                        label: DefaultRoutingLabel::try_from("0000.0000.0000.0015").expect("cjdns base test example failed"),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0
                    }
                ]),
                node_encryption_key: CJDNSPublicKey::try_from("z15pzyd9wgzs2g5np7d3swrqc1533yb7xx9dq0pvrqrqs42uwgq0.k".to_string())
                    .expect("cjdns base test example failed"),
                node_ip6: CJDNS_IP6::try_from("fc49:11cb:38c2:8d42:9865:7b8e:0d67:11b3".to_string()).expect("cjdns base test example failed"),
                binary: serialized_data::AnnouncementPacket(test_bytes),
                binary_hash: test_bytes_hash
            }
        )
    }
}