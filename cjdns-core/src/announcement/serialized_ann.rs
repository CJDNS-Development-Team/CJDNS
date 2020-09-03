use std::convert::TryFrom;

use sodiumoxide::crypto::hash::sha512::{hash, Digest};
use sodiumoxide::crypto::sign::ed25519::{verify_detached, PublicKey, Signature};

use crate::{
    deserialize_forms,
    keys::{CJDNSPublicKey, CJDNS_IP6},
    EncodingScheme, RoutingLabel,
};

use super::errors::*;
use super::models::{Announcement, AnnouncementEntities, AnnouncementHeader, Entity, SlotsArray,};

const ANNOUNCEMENT_MIN_SIZE: usize = HEADER_SIZE;
const HEADER_SIZE: usize = SIGN_SIZE + SIGN_KEY_SIZE + IP_SIZE + 8;
const SIGN_SIZE: usize = 64;
const SIGN_KEY_SIZE: usize = 32;
const IP_SIZE: usize = 16;

pub mod serialized_data {
    use super::*;

    type Result<T> = std::result::Result<T, PacketError>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AnnouncementPacket(Vec<u8>);

    impl AnnouncementPacket {
        /// Instantiates wrapper on announcement message
        pub fn try_new(ann_data: Vec<u8>) -> Result<Self> {
            if ann_data.len() < ANNOUNCEMENT_MIN_SIZE {
                return Err(PacketError::CannotInstantiatePacket);
            }
            Ok(Self(ann_data))
        }

        /// Checks announcement message signature validity
        pub fn check(&self) -> Result<()> {
            let signature = Signature::from_slice(self.get_signature_bytes()).expect("signature size != 64");
            let public_sign_key = PublicKey::from_slice(self.get_pub_key_bytes()).expect("public key size != 32");
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::EncodingSchemeForm;
        use sodiumoxide::*;

        fn join(slice1: &[u8], slice2: &[u8]) -> Vec<u8> {
            slice1.iter().chain(slice2.iter()).map(|&x| x).collect()
        }

        fn hex_to_bytes(hex_string: String) -> Vec<u8> {
            hex::decode(hex_string).expect("invalid hex string")
        }

        #[test]
        fn test_packet_creation() {
            init().expect("sodium init failed");

            // actually, length could be greater than 144
            for packet_length in 0..144 {
                let packet_data = randombytes::randombytes(packet_length);
                let packet = AnnouncementPacket::try_new(packet_data);

                let valid_case = packet_length >= ANNOUNCEMENT_MIN_SIZE;
                if valid_case {
                    assert!(packet.is_ok());
                } else {
                    assert!(packet.is_err());
                }
            }
        }

        #[test]
        fn test_packet_pure_fns() {
            init().expect("sodium init failed");

            let header_data = randombytes::randombytes(HEADER_SIZE);
            for entities_len in 0..100 {
                let entities_data = randombytes::randombytes(entities_len);
                let announcement_data = join(&header_data, &entities_data);
                let packet = AnnouncementPacket::try_new(announcement_data.to_vec()).expect("invalid data len");

                assert_eq!(packet.get_signed_data(), &announcement_data[SIGN_SIZE..]);
                assert_eq!(packet.get_signature_bytes(), &header_data[..SIGN_SIZE]);
                assert_eq!(packet.get_pub_key_bytes(), &header_data[SIGN_SIZE..][..SIGN_KEY_SIZE]);
                assert_eq!(packet.get_header_bytes(), header_data.as_slice());
                assert_eq!(packet.get_entities_bytes(), entities_data.as_slice());
            }
        }

        #[test]
        fn test_sign_check() {
            init().expect("sodium init failed");

            fn create_signed_header() -> Vec<u8> {
                let (sodium_pk, sodium_sk) = crypto::sign::gen_keypair();
                let header_data_to_sign = {
                    let rest_header_data = randombytes::randombytes(HEADER_SIZE - SIGN_SIZE - SIGN_KEY_SIZE);
                    join(sodium_pk.as_ref(), &rest_header_data)
                };
                let sign = crypto::sign::sign_detached(&header_data_to_sign, &sodium_sk);
                join(sign.as_ref(), &header_data_to_sign)
            };

            for _ in 0..100 {
                let packet = AnnouncementPacket::try_new(create_signed_header()).expect("invalid packet data len");
                assert!(packet.check().is_ok());
            }
        }

        #[test]
        fn test_parse() {
            let test_data_bytes = {
                // header hex data
                let sign = "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09";
                let pub_key = "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2";
                let super_node_ip = "fc928136dc1fe6e04ef6a6dd7187b85f";
                let rest_header_data = "00001576462f6f69";

                // entities hexed data
                let version_entity = "04020012";
                let pad = "01";
                let encoding_scheme_entity = "07006114458100";
                let peer_entity = "200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015";

                let s = format!(
                    "{}{}{}{}{}{}{}{}",
                    sign, pub_key, super_node_ip, rest_header_data, version_entity, pad, encoding_scheme_entity, peer_entity
                );

                hex_to_bytes(s)
            };
            let test_bytes_hash = hash(&test_data_bytes);

            let ann_packet = AnnouncementPacket::try_new(test_data_bytes.clone()).expect("wrong packet size");
            assert!(ann_packet.check().is_ok());

            let parse_res = ann_packet.parse().expect("failed parsing basic `cjdnsann` test");
            assert_eq!(
                parse_res,
                Announcement {
                    header: AnnouncementHeader {
                        signature:
                            "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09"
                                .to_string(),
                        pub_signing_key: "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2".to_string(),
                        super_node_ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                        version: 1,
                        is_reset: true,
                        timestamp: 1474857989878
                    },
                    entities: vec![
                        Entity::NodeProtocolVersion(18),
                        Entity::EncodingScheme {
                            hex: "6114458100".to_string(),
                            scheme: EncodingScheme::new(&vec![
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
                            ])
                        },
                        Entity::Peer {
                            ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                            label: Some(RoutingLabel::<u32>::try_new(21).expect("zero routing label bits")),
                            mtu: 0,
                            peer_num: 65535,
                            unused: 4294967295,
                            encoding_form_number: 0,
                            flags: 0
                        }
                    ],
                    node_encryption_key: CJDNSPublicKey::try_from("z15pzyd9wgzs2g5np7d3swrqc1533yb7xx9dq0pvrqrqs42uwgq0.k".to_string())
                        .expect("failed pub key creation"),
                    node_ip6: CJDNS_IP6::try_from("fc49:11cb:38c2:8d42:9865:7b8e:0d67:11b3".to_string()).expect("failed ip6 creation"),
                    binary: AnnouncementPacket(test_data_bytes),
                    binary_hash: test_bytes_hash
                }
            )
        }
    }
}

mod parser {
    use std::slice::Iter;

    use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;

    use super::*;

    type Result<T> = std::result::Result<T, ParserError>;

    const PEER_TYPE: u8 = 1;
    const VERSION_TYPE: u8 = 2;
    const LINK_STATE_TYPE: u8 = 3;
    const ENCODING_SCHEME_TYPE: u8 = 0;

    const ENTITY_MAX_SIZE: usize = 255;

    const PEER_ENTITY_SIZE: usize = 32;
    const VERSION_ENTITY_SIZE: usize = 4;
    const LINK_STATE_ENTITY_MIN_SIZE: usize = 2;
    // it's actually `2` in cjdnsann doc, but it's too little, because min size for encoding scheme bytes to be deserialized is `2`.
    // So we have 2 bytes for encoded type and length and minimum 2 bytes for encoding scheme deserialization.
    const ENCODING_SCHEME_ENTITY_MIN_SIZE: usize = 4;

    // Dividing logic from DS (`AnnouncementPacket`)
    pub(super) fn parse(packet: serialized_data::AnnouncementPacket) -> Result<Announcement> {
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
        if header_data.len() != HEADER_SIZE {
            return Err(ParserError::CannotParseHeader("invalid data size"));
        }
        let (signature_data, header_without_sign) = header_data.split_at(SIGN_SIZE);
        let signature = hex::encode(signature_data);

        let (signing_key_data, header_without_sign_n_key) = header_without_sign.split_at(SIGN_KEY_SIZE);
        let pub_signing_key = hex::encode(signing_key_data);

        let (super_node_data, rest_header) = header_without_sign_n_key.split_at(IP_SIZE);
        let super_node_ip = CJDNS_IP6::try_from(super_node_data.to_vec()).or(Err(ParserError::CannotParseHeader("failed ip6 creation from bytes data")))?;

        assert_eq!(rest_header.len(), 8, "Header size != 120 bytes");
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

        let mut timestamp = u64::from_be_bytes(<[u8; 8]>::try_from(rest_header).expect("slice size != 8"));
        // removing `version` and `is_reset` bits form timestamp bytes
        timestamp >>= 4;

        Ok(AnnouncementHeader {
            signature,
            pub_signing_key,
            super_node_ip6: super_node_ip,
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
        let ok = unsafe {
            // call to an extern function which uses raw pointers
            // considered safe, because data under these pointers is consistent during function call
            crypto_sign_ed25519_pk_to_curve25519(curve25519_key_bytes.as_mut_ptr(), public_sign_key.0.as_ptr()) == 0
        };
        if !ok {
            return Err(ParserError::CannotParseAuthData("Conversion from x25519 to curve25519 failed"));
        }
        let node_encryption_key = CJDNSPublicKey::from(curve25519_key_bytes);
        let node_ip6 = CJDNS_IP6::try_from(&node_encryption_key).or(Err(ParserError::CannotParseAuthData("failed ip6 creation from auth pub key")))?;
        Ok((node_encryption_key, node_ip6))
    }

    fn parse_entities(entities_data: &[u8]) -> Result<AnnouncementEntities> {
        let mut parsed_entities = Vec::new();
        let mut idx = 0;
        while idx < entities_data.len() {
            let encoded_entity_len = entities_data[idx] as usize;
            let entity_data = entities_data
                .get(idx..idx + encoded_entity_len)
                .ok_or(ParserError::CannotParseEntity("entity with invalid encoded length"))?;

            if encoded_entity_len == 0 {
                return Err(ParserError::CannotParseEntity("zero entity inside entities data"));
            }
            if encoded_entity_len == 1 {
                idx += 1;
                continue;
            }

            let &entity_type = entities_data.get(idx + 1).expect("entity data length != encoded length in it");
            let parsed_entity = parse_entity(entity_type, entity_data)?;
            if let Some(entity) = parsed_entity {
                parsed_entities.push(entity)
            }

            idx += entities_data[idx] as usize;
        }

        Ok(parsed_entities)
    }

    fn parse_entity(entity_type: u8, entity_data: &[u8]) -> Result<Option<Entity>> {
        // First byte of each entity data is its length. The second byte is its type. So "non meta" data of each entity starts from index 2 (3rd byte).
        let parsing_data = &entity_data[2..];
        match entity_type {
            ENCODING_SCHEME_TYPE => {
                if entity_data.len() < ENCODING_SCHEME_ENTITY_MIN_SIZE || entity_data.len() > ENTITY_MAX_SIZE {
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
            LINK_STATE_TYPE => {
                if entity_data.len() < LINK_STATE_ENTITY_MIN_SIZE || entity_data.len() > ENTITY_MAX_SIZE {
                    return Err(ParserError::CannotParseEntity("invalid link state data size"));
                }
                let link_state_entity = parse_link_state(parsing_data)?;
                Ok(Some(link_state_entity))
            }
            _ => Ok(None),
        }
    }

    fn parse_encoding_scheme(encoding_scheme_data: &[u8]) -> Result<Entity> {
        let hex = hex::encode(encoding_scheme_data);
        let scheme_forms = deserialize_forms(encoding_scheme_data).or(Err(ParserError::CannotParseEntity("encoding scheme deserialization failed")))?;
        let scheme = EncodingScheme::new(&scheme_forms);
        Ok(Entity::EncodingScheme { hex, scheme })
    }

    fn parse_version(version_data: &[u8]) -> Result<Entity> {
        assert_eq!(version_data.len(), 2);
        let version = u16::from_be_bytes(<[u8; 2]>::try_from(version_data).expect("version slice length != 2"));
        Ok(Entity::NodeProtocolVersion(version))
    }

    fn parse_peer(peer_data: &[u8]) -> Result<Entity> {
        assert_eq!(peer_data.len(), 30);
        let mut peer_data_iter = peer_data.iter();
        let mut take_peer_bytes = |n: usize| peer_data_iter.by_ref().take(n).map(|&byte| byte).collect::<Vec<u8>>();
        let (encoding_form_number, flags) = {
            let efn_f = take_peer_bytes(2);
            let err_msg = "peer data is empty";
            let (&encoding_form_number, &flags) = (efn_f.first().expect(err_msg), efn_f.last().expect(err_msg));
            (encoding_form_number, flags)
        };
        let mtu = {
            let mtu8 = u16::from_be_bytes(<[u8; 2]>::try_from(take_peer_bytes(2).as_slice()).expect("mtu slice size != 2"));
            mtu8 as u32 * 8
        };
        let peer_num = u16::from_be_bytes(<[u8; 2]>::try_from(take_peer_bytes(2).as_slice()).expect("peer_num slice size != 2"));
        let unused = u32::from_be_bytes(<[u8; 4]>::try_from(take_peer_bytes(4).as_slice()).expect("unused slice size != 4"));
        let ip6 = CJDNS_IP6::try_from(take_peer_bytes(16)).or(Err(ParserError::CannotParseEntity("failed ip6 creation from entity bytes")))?;
        let label = {
            let label_bits = u32::from_be_bytes(<[u8; 4]>::try_from(take_peer_bytes(4).as_slice()).expect("label slice size != 4"));
            // A label of 0 indicates that the route is being withdrawn and it is no longer usable. Handling of zero label is not a job for parser
            // So we return an Option
            RoutingLabel::<u32>::try_new(label_bits)
        };
        Ok(Entity::Peer {
            ip6,
            label,
            mtu,
            peer_num,
            unused,
            encoding_form_number,
            flags,
        })
    }

    // todo refactor
    fn parse_link_state(link_state_data: &[u8]) -> Result<Entity> {
        assert!(link_state_data.len() >= 1);
        let mut link_state_iter = link_state_data.iter();
        let &pads_amount = link_state_iter.next().expect("wrong link state data len");
        let zero_pads = link_state_iter.by_ref().take(pads_amount as usize).filter(|&&x| x == 0).count();
        if zero_pads != pads_amount as usize {
            return Err(ParserError::CannotParseLinkState("non zero pad found in pad range"));
        }
        let node_id = var_int_pop(&mut link_state_iter)?;
        let starting_point = var_int_pop(&mut link_state_iter)?;
        let mut lag_slots = SlotsArray::default();
        let mut drop_slots = SlotsArray::default();
        let mut kb_recv_slots = SlotsArray::default();
        let mut i = starting_point;
        while link_state_iter.as_slice().len() != 0 {
            lag_slots[i as usize] = var_int_pop(&mut link_state_iter)?;
            drop_slots[i as usize] = var_int_pop(&mut link_state_iter)?;
            kb_recv_slots[i as usize] = var_int_pop(&mut link_state_iter)?;
            i = (i + 1) % 18;
        }
        Ok(Entity::LinkState {
            node_id,
            starting_point,
            lag_slots,
            drop_slots,
            kb_recv_slots,
        })
    }

    // todo refactor
    fn var_int_pop(link_state_iter: &mut Iter<u8>) -> Result<u32> {
        let mut output = 0;
        let len = link_state_iter.as_slice().len();
        let &byte = link_state_iter.as_slice().first().ok_or(ParserError::CannotParseLinkState("wrong iter len"))?;
        let runt_err = Err(ParserError::CannotParseLinkState("runt"));
        if len < 9 {
            if len < 5 {
                if len < 3 {
                    if len < 1 {
                        return runt_err;
                    }
                    if byte >= 0xfd {
                        return runt_err;
                    }
                } else if byte >= 0xfe {
                    return runt_err;
                }
            } else if byte >= 0xff {
                return runt_err;
            }
        }
        output = check_current_byte_fall_through(byte, output, link_state_iter);
        Ok(output)
    }

    // todo refactor
    fn check_current_byte_fall_through(current_byte: u8, mut current_output: u32, link_state_iter: &mut Iter<u8>) -> u32 {
        match current_byte {
            0xff => {
                for _ in 0..4 {
                    current_output |= *link_state_iter.by_ref().skip(1).next().expect("link state data len is too small") as u32;
                    current_output <<= 8;
                }
                check_current_byte_fall_through(0xfe, current_output, link_state_iter)
            }
            0xfe => {
                for _ in 0..2 {
                    current_output |= *link_state_iter.by_ref().skip(1).next().expect("link state data len is too small") as u32;
                    current_output <<= 8;
                }
                check_current_byte_fall_through(0xfe, current_output, link_state_iter)
            }
            0xfd => {
                current_output |= *link_state_iter.by_ref().skip(1).next().expect("link state data len is too small") as u32;
                current_output <<= 8;
                check_current_byte_fall_through(u8::default(), current_output, link_state_iter)
            }
            _ => {
                current_output |= *link_state_iter.next().expect("link state data len is too small") as u32;
                current_output
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use sodiumoxide::*;

        use super::*;
        use crate::keys::{BytesRepr, CJDNSKeysApi};

        #[test]
        fn test_parse_header() {
            let keys_api = CJDNSKeysApi::new().expect("sodium init failed");
            let rand_data = randombytes::randombytes(72);
            let (random_signature, random_timestamp) = rand_data.split_at(64);
            let keys = keys_api.key_pair();

            let ann_timestamp = {
                let mut timestamp = u64::from_be_bytes(<[u8; 8]>::try_from(random_timestamp).expect("slice array size != 8"));
                timestamp >>= 4;
                timestamp
            };
            let version = random_timestamp[7] & 7;
            let is_reset = (random_timestamp[7] >> 3) & 1 == 1;

            let header_bytes = {
                let mut header_bytes = Vec::with_capacity(120);
                header_bytes.extend_from_slice(random_signature);
                header_bytes.extend_from_slice(&keys.public_key.bytes());
                header_bytes.extend_from_slice(&keys.ip6.bytes());
                header_bytes.extend_from_slice(random_timestamp);
                header_bytes
            };

            let parsed_header = parse_header(&header_bytes).expect("parse failed");
            assert_eq!(
                parsed_header,
                AnnouncementHeader {
                    signature: hex::encode(random_signature),
                    pub_signing_key: hex::encode(keys.public_key.bytes()),
                    super_node_ip6: keys.ip6,
                    timestamp: ann_timestamp,
                    version,
                    is_reset
                }
            )
        }

        #[test]
        fn test_parse_header_invalid_len() {
            init().expect("sodium init failed");

            let invalid_header_lengths = (0..=255).filter(|&x| x != HEADER_SIZE);
            for len in invalid_header_lengths {
                let random_header_bytes = randombytes::randombytes(len);
                assert!(parse_header(&random_header_bytes).is_err())
            }
        }

        #[test]
        fn test_parse_ann_with_no_entities() {
            let valid_hexed_header =
                // signature
                "9dcdafaf6a129d4194eb52586ec81ecbf7f52abf183268a314e19e066baa7bfbe01121ba42ff8fa41356420894d576ce0a0105577cca0e50d945283c18d89c07".to_string() +
                // pub key
                "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2" +
                // ip6
                "fc928136dc1fe6e04ef6a6dd7187b85f" +
                // timestamp-version-is_reset
                "0000157354c540c1";
            let header_bytes = hex::decode(valid_hexed_header).expect("invalid hex string");
            let parsed_announcement = parser::parse(serialized_data::AnnouncementPacket::try_new(header_bytes).expect("invalid bytes len")).expect("invalid ann data");
            assert_eq!(parsed_announcement.entities, vec![]);
        }

        #[test]
        fn test_parse_entities() {
            let invalid_entities_data_hexed = [
                // zero length entity
                "00123123132412",
                "02050001",
                // zero byte at the end - corrupt
                "02050100",
                // invalid encoded len: not equal to actual buffer len
                "02",
                "0305",
                "02050302",
                // invalid data size for entities
                "030201",     // version entity len should be 4
                "0501000220", // peer entity len should be 32
                // mixing valid and invalid
                "030507006114458100",                                                 // 0305 and valid encoding entity
                "0204020012",                                                         // 02 and valid version entity
                "20200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015", // 20 and valid peer entity
            ];
            for &invalid_entity_data in invalid_entities_data_hexed.iter() {
                let data_bytes = hex::decode(invalid_entity_data).expect("invalid hex string");
                assert!(parse_entities(&data_bytes).is_err());
            }

            let valid_tests = vec![
                // no entities passed
                ("", vec![]),
                (
                    "200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000003",
                    vec![Entity::Peer {
                        ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                        label: Some(RoutingLabel::<u32>::try_new(3).expect("zero label bits")),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0,
                    }],
                ),
                (
                    "04020002200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000020",
                    vec![
                        Entity::NodeProtocolVersion(2),
                        Entity::Peer {
                            ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                            label: Some(RoutingLabel::<u32>::try_new(32).expect("zero label bits")),
                            mtu: 0,
                            peer_num: 65535,
                            unused: 4294967295,
                            encoding_form_number: 0,
                            flags: 0,
                        },
                    ],
                ),
                (
                    // with some pads
                    "0402000201010101200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000013",
                    vec![
                        Entity::NodeProtocolVersion(2),
                        Entity::Peer {
                            ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                            label: Some(RoutingLabel::<u32>::try_new(19).expect("zero label bits")),
                            mtu: 0,
                            peer_num: 65535,
                            unused: 4294967295,
                            encoding_form_number: 0,
                            flags: 0,
                        },
                    ],
                ),
                (
                    // with unrecognised entities at the beginning and at the end
                    "020701200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000003030510",
                    vec![Entity::Peer {
                        ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                        label: Some(RoutingLabel::<u32>::try_new(3).expect("zero label bits")),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0,
                    }],
                ),
                (
                    // all of them are unrecognised
                    "03100102050504020304",
                    vec![],
                ),
            ];
            for (test_data_hexed, res) in valid_tests.into_iter() {
                let test_bytes = hex::decode(test_data_hexed).expect("invalid hex string");
                let parsed_entity = parse_entities(&test_bytes).expect("invalid entity passed");
                assert_eq!(parsed_entity, res);
            }
        }

        #[test]
        fn test_multiple_peers() {
            let multiple_peer_entity_hex = {
                let peer_data_hex = "200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015";
                format!("{}{}{}", peer_data_hex, peer_data_hex, peer_data_hex)
            };
            let entities_data_vec = hex::decode(multiple_peer_entity_hex).expect("invalid hex string");

            let parsed_peer = Entity::Peer {
                ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
                label: Some(RoutingLabel::<u32>::try_new(21).expect("zero label bits")),
                mtu: 0,
                peer_num: 65535,
                unused: 4294967295,
                encoding_form_number: 0,
                flags: 0,
            };
            let parsed_entities = parse_entities(&entities_data_vec).expect("parsing entities failed");

            assert_eq!(parsed_entities, vec![parsed_peer; 3]);
        }

        #[test]
        fn test_parse_link_state() {
            let hexed_data = "2003060000000000000410130001120002130002130000140003120001130001";
            let test_bytes = hex::decode(hexed_data).expect("invalid hex string");
            let res = parse_entities(&test_bytes).expect("invalid entity");
            assert_eq!(
                res,
                vec![Entity::LinkState {
                    node_id: 4,
                    starting_point: 16,
                    lag_slots: [19, 19, 20, 18, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 18],
                    drop_slots: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    kb_recv_slots: [2, 0, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]
                }]
            )
        }
    }
}