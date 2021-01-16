use std::convert::TryFrom;

use cjdns_core::{deserialize_scheme, RoutingLabel};
use cjdns_crypto::hash::sha512;
use cjdns_crypto::sign::ed25519;
use cjdns_keys::{CJDNS_IP6, CJDNSPublicKey};

use super::errors::*;
use super::models::{Announcement, AnnouncementEntities, AnnouncementHeader, Entity, LinkStateSlots};

const ANNOUNCEMENT_MIN_SIZE: usize = HEADER_SIZE;
const HEADER_SIZE: usize = SIGN_SIZE + SIGN_KEY_SIZE + IP_SIZE + 8;
const SIGN_SIZE: usize = 64;
const SIGN_KEY_SIZE: usize = 32;
const IP_SIZE: usize = 16;

pub mod serialized_data {
    //! This module exports logic on serialized announcement message.

    use super::*;

    type Result<T> = std::result::Result<T, PacketError>;

    /// Serialized announcement message. A thin wrapper over announcement packet bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AnnouncementPacket(Vec<u8>);

    impl AnnouncementPacket {
        /// Wrap raw announcement message bytes.
        ///
        /// Results in error if `ann_data` packet length is less than 120 bytes (incomplete message header).
        ///
        /// # Note
        ///
        /// It is valid for announcement to have just header with no data.
        pub fn try_new(ann_data: Vec<u8>) -> Result<Self> {
            if ann_data.len() < ANNOUNCEMENT_MIN_SIZE {
                return Err(PacketError::CannotInstantiatePacket);
            }
            Ok(Self(ann_data))
        }

        /// Checks announcement message digital signature validity.
        /// Gets signature, public signing key and signed data bytes from announcement packet and performs signature check using
        /// [crypto_sign_verify_detached](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures).
        pub fn check(&self) -> Result<()> {
            let signature = ed25519::Signature::try_from(self.get_signature_bytes()).expect("internal error: signature size != 64");
            let public_sign_key = ed25519::PublicKey::from_slice(self.get_pub_key_bytes()).expect("internal error: public key size != 32");
            let signed_data = self.get_signed_data();
            if ed25519::verify_detached(&signature, signed_data, &public_sign_key) {
                return Ok(());
            }
            Err(PacketError::InvalidPacketSignature)
        }

        /// Parses announcement packet and creates deserialized announcement message, consuming this packet.
        pub fn parse(self) -> Result<Announcement> {
            parser::parse(self).map_err(PacketError::CannotParsePacket)
        }

        pub(super) fn get_hash(&self) -> sha512::Digest {
            sha512::hash(&self.0)
        }

        pub(super) fn get_entities_bytes(&self) -> &[u8] {
            &self.0[HEADER_SIZE..]
        }

        pub(super) fn get_header_bytes(&self) -> &[u8] {
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

        pub fn into_inner(self) -> Vec<u8> {
            self.0
        }
    }

    #[cfg(test)]
    mod tests {
        use cjdns_core::{EncodingScheme, EncodingSchemeForm};
        use cjdns_crypto::sign;

        use crate::models::{AnnHash, PeerData};

        use super::*;

        fn join(slice1: &[u8], slice2: &[u8]) -> Vec<u8> {
            slice1.iter().chain(slice2.iter()).map(|&x| x).collect()
        }

        fn hex_to_bytes(hex_string: String) -> Vec<u8> {
            hex::decode(hex_string).expect("invalid hex string")
        }

        fn encoding_scheme(forms: &[EncodingSchemeForm]) -> EncodingScheme {
            EncodingScheme::try_new(forms).expect("invalid scheme")
        }

        fn encoding_form(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
            EncodingSchemeForm::try_new(bit_count, prefix_len, prefix).expect("invalid form")
        }

        #[test]
        fn test_packet_creation() {
            for packet_length in 0..144 {
                let packet_data = vec![0; packet_length];
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
            let header_data = vec![0; HEADER_SIZE];
            for entities_len in 0..100 {
                let entities_data = vec![0; entities_len];
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
            fn create_signed_header() -> Vec<u8> {
                let (sodium_pk, sodium_sk) = sign::gen_keypair(); // random numbers generated here - test might be unstable
                let header_data_to_sign = {
                    let rest_header_data = vec![0; HEADER_SIZE - SIGN_SIZE - SIGN_KEY_SIZE];
                    join(sodium_pk.as_ref(), &rest_header_data)
                };
                let sign = sign::sign_detached(&header_data_to_sign, &sodium_sk);
                join(sign.as_ref(), &header_data_to_sign)
            };

            let packet = AnnouncementPacket::try_new(create_signed_header()).expect("invalid packet data len");
            assert!(packet.check().is_ok());
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
            let test_bytes_hash = AnnHash::from_digest(sha512::hash(&test_data_bytes));

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
                        snode_ip: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                        version: 1,
                        is_reset: true,
                        timestamp: 1474857989878
                    },
                    entities: vec![
                        Entity::NodeProtocolVersion(18),
                        Entity::EncodingScheme {
                            hex: "6114458100".to_string(),
                            scheme: encoding_scheme(&vec![encoding_form(3, 1, 1), encoding_form(5, 2, 2), encoding_form(8, 2, 0),])
                        },
                        Entity::Peer(PeerData {
                            ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                            label: Some(RoutingLabel::<u32>::try_new(21).expect("zero routing label bits")),
                            mtu: 0,
                            peer_num: 65535,
                            unused: 4294967295,
                            encoding_form_number: 0,
                            flags: 0
                        })
                    ],
                    node_pub_key: CJDNSPublicKey::try_from("z15pzyd9wgzs2g5np7d3swrqc1533yb7xx9dq0pvrqrqs42uwgq0.k").expect("failed pub key creation"),
                    node_ip: CJDNS_IP6::try_from("fc49:11cb:38c2:8d42:9865:7b8e:0d67:11b3").expect("failed ip6 creation"),
                    binary: test_data_bytes,
                    hash: test_bytes_hash
                }
            )
        }
    }
}

mod parser {
    //! Parser module encapsulating logic for announcement data parsing

    use cjdns_bytes::{ExpectedSize, Reader};
    use cjdns_crypto::sign_ext::sign_ed25519_pk_to_curve25519;
    use serialized_data::AnnouncementPacket;

    use crate::models::{AnnHash, LINK_STATE_SLOTS, LinkStateData, PeerData};
    use crate::var_int::read_var_int;

    use super::*;

    const PEER_TYPE: u8 = 1;
    const VERSION_TYPE: u8 = 2;
    const LINK_STATE_TYPE: u8 = 3;
    const ENCODING_SCHEME_TYPE: u8 = 0;

    // entity data size without encoded meta-data (i.g., length and type)
    const PEER_ENTITY_SIZE: usize = 30;
    const VERSION_ENTITY_SIZE: usize = 2;
    const ENCODING_SCHEME_ENTITY_MIN_SIZE: usize = 2;
    const STATE_SLOTS_SIZE: usize = LINK_STATE_SLOTS as usize;

    pub(super) fn parse(packet: AnnouncementPacket) -> Result<Announcement, ParserError> {
        let header = parse_header(packet.get_header_bytes())?;
        let (node_encryption_key, node_ip6) = parse_sender_auth_data(packet.get_pub_key_bytes())?;
        let entities = parse_entities(packet.get_entities_bytes())?;
        let digest = packet.get_hash();
        Ok(Announcement {
            header,
            node_pub_key: node_encryption_key,
            node_ip: node_ip6,
            entities,
            hash: AnnHash::from_digest(digest),
            binary: packet.into_inner(),
        })
    }

    fn parse_header(header_data: &[u8]) -> Result<AnnouncementHeader, ParserError> {
        let mut data_reader = Reader::new(header_data);
        let (signature_bytes, sign_key_bytes, snode_bytes, last_byte, timestamp) = data_reader
            .read(ExpectedSize::Exact(HEADER_SIZE), |r| {
                let signature_bytes = r.read_slice(SIGN_SIZE)?;
                let sign_key_bytes = r.read_slice(SIGN_KEY_SIZE)?;
                let snode_bytes = r.read_slice(IP_SIZE)?;
                let &last_byte = r.peek_remainder().last().expect("internal error: unexpected buffer size");
                let timestamp = r.read_u64_be()?;
                Ok((signature_bytes, sign_key_bytes, snode_bytes, last_byte, timestamp))
            })
            .map_err(|_| ParserError::CannotParseHeader("invalid data size"))?;

        let signature = hex::encode(signature_bytes);
        let pub_signing_key = hex::encode(sign_key_bytes);
        let snode_ip6 = CJDNS_IP6::try_from(snode_bytes).map_err(|_| ParserError::CannotParseHeader("failed ip6 creation from received data"))?;
        let version = {
            // version is encoded in 3 least significant bits
            // For example:
            // last byte is NNNN_NNNN, where N is either 0 or 1
            // so version is 0000_0NNN = NNNN_NNNN & 111
            last_byte & 7
        };
        let is_reset = {
            // this flag is encoded in the fourth bit in least significant order
            // For example:
            // last byte is AAAA_AAAA, where N is either 0 or 1
            // so reset flag is the bit N in last byte: AAAA_NAAA
            (last_byte >> 3) & 1 == 1
        };
        // removing `version` and `is_reset` bits form timestamp bytes
        let timestamp = timestamp >> 4;

        Ok(AnnouncementHeader {
            signature,
            pub_signing_key,
            snode_ip: snode_ip6,
            version,
            is_reset,
            timestamp,
        })
    }

    /// It's expected, that `pub_key_bytes` len is 32. Otherwise function will panic.
    ///
    /// Currently, the argument is provided by `AnnouncementPacket::get_pub_key_bytes` method, which returns a slice of the expected len.
    fn parse_sender_auth_data(pub_key_bytes: &[u8]) -> Result<(CJDNSPublicKey, CJDNS_IP6), ParserError> {
        let public_sign_key = ed25519::PublicKey::from_slice(pub_key_bytes).expect("internal error: public key size != 32");
        let res = sign_ed25519_pk_to_curve25519(public_sign_key);
        let curve25519_key_bytes = match res {
            Ok(res) => res,
            Err(_) => {
                return Err(ParserError::CannotParseAuthData("conversion from x25519 to curve25519 failed"));
            }
        };
        let node_encryption_key = CJDNSPublicKey::from(curve25519_key_bytes);
        let node_ip6 = CJDNS_IP6::try_from(&node_encryption_key).map_err(|_| ParserError::CannotParseAuthData("failed ip6 creation from received data"))?;
        Ok((node_encryption_key, node_ip6))
    }

    fn parse_entities(entities_data: &[u8]) -> Result<AnnouncementEntities, ParserError> {
        parse_entities_impl(entities_data).map_err(ParserError::CannotParseEntity)
    }

    fn parse_entities_impl(entities_data: &[u8]) -> Result<AnnouncementEntities, EntityParserError> {
        let mut parsed_entities = Vec::new();
        let mut data_reader = Reader::new(entities_data);
        while !data_reader.is_empty() {
            // each valid entity is encoded in `entities_data` as `[entity_length][entity_type][entity_data]`
            // `entity_length` must be `2 + entity_data.len()`, where `2` states for `entity_length` and `entity_type` bytes.
            let entity_length = data_reader.read_u8().expect("internal error: empty buffer");
            if entity_length == 0 {
                return Err(EntityParserError::BadData("zero length entity"));
            }
            // padding
            if entity_length == 1 {
                continue;
            }
            let entity_data = data_reader
                // reading `entity_length - 1`, because entity length byte has been already read
                .read_slice((entity_length - 1) as usize)
                .map_err(|_| EntityParserError::BadData("encoded entity len > entities data remainder size"))?;

            let parsed_entity = parse_entity(entity_data)?;
            if let Some(entity) = parsed_entity {
                parsed_entities.push(entity)
            }
        }
        Ok(parsed_entities)
    }

    /// The function argument represents a properly encoded entity.
    /// Properly encoded entity has the structure: `[entity_length][entity_type][entity_data]`.
    /// Entity length is read in `parse_entities_impl`, so received `entity_data` only has entity type and parsing data.
    fn parse_entity(entity_data: &[u8]) -> Result<Option<Entity>, EntityParserError> {
        let &entity_type = entity_data.get(0).expect("internal error: entity data without entity type");
        let parsing_data = &entity_data[1..];
        match entity_type {
            ENCODING_SCHEME_TYPE => Ok(Some(parse_encoding_scheme(parsing_data)?)),
            PEER_TYPE => Ok(Some(parse_peer(parsing_data)?)),
            VERSION_TYPE => Ok(Some(parse_version(parsing_data)?)),
            LINK_STATE_TYPE => Ok(Some(parse_link_state(parsing_data)?)),
            _ => Ok(None),
        }
    }

    fn parse_encoding_scheme(encoding_scheme_data: &[u8]) -> Result<Entity, EntityParserError> {
        let scheme_data = Reader::new(encoding_scheme_data)
            .read(ExpectedSize::NotLessThan(ENCODING_SCHEME_ENTITY_MIN_SIZE), |r| Ok(r.read_remainder()))
            .map_err(|_| EntityParserError::InvalidSize)?;
        let hex = hex::encode(scheme_data);
        let scheme = deserialize_scheme(scheme_data).map_err(|_| EntityParserError::BadData("encoding scheme bytes can't be deserialized"))?;
        Ok(Entity::EncodingScheme { hex, scheme })
    }

    fn parse_version(version_data: &[u8]) -> Result<Entity, EntityParserError> {
        let version = Reader::new(version_data)
            .read(ExpectedSize::Exact(VERSION_ENTITY_SIZE), |r| Ok(r.read_u16_be()?))
            .map_err(|_| EntityParserError::InvalidSize)?;
        Ok(Entity::NodeProtocolVersion(version))
    }

    fn parse_peer(peer_data: &[u8]) -> Result<Entity, EntityParserError> {
        let mut data_reader = Reader::new(peer_data);
        let (encoding_form_number, flags, mtu8, peer_num, unused, ip6_bytes, label_bits) = data_reader
            .read(ExpectedSize::Exact(PEER_ENTITY_SIZE), |r| {
                let encoding_form_number = r.read_u8()?;
                let flags = r.read_u8()?;
                let mtu8 = r.read_u16_be()?;
                let peer_num = r.read_u16_be()?;
                let unused = r.read_u32_be()?;
                let ip6_bytes = r.read_slice(16)?;
                let label_bits = r.read_u32_be()?;
                Ok((encoding_form_number, flags, mtu8, peer_num, unused, ip6_bytes, label_bits))
            })
            .map_err(|_| EntityParserError::InvalidSize)?;

        let mtu = mtu8 as u32 * 8;
        let ipv6 = CJDNS_IP6::try_from(ip6_bytes).map_err(|_| EntityParserError::BadData("failed ip6 creation from peer bytes"))?;
        // A label of 0 indicates that the route is being withdrawn and it is no longer usable. Handling of zero label is not a job for parser
        // So we return an Option
        let label = RoutingLabel::<u32>::try_new(label_bits);
        Ok(Entity::Peer(PeerData {
            ipv6,
            label,
            mtu,
            peer_num,
            unused,
            encoding_form_number,
            flags,
        }))
    }

    /// C implementation: https://github.com/cjdelisle/cjdns/blob/d832e26951a2af083b4defb576fe1f0beeef6327/subnode/LinkState.h#L127
    fn parse_link_state(link_state_data: &[u8]) -> Result<Entity, EntityParserError> {
        let mut data_reader = Reader::new(link_state_data);
        {
            let pads_amount = data_reader.read_u8().map_err(|_| EntityParserError::InsufficientData)?;
            let zero_pads = {
                let pads = data_reader.read_slice(pads_amount as usize).map_err(|_| EntityParserError::InsufficientData)?;
                pads.iter().filter(|&&x| x == 0).count()
            };
            if zero_pads != pads_amount as usize {
                return Err(EntityParserError::BadData("non zero pad"));
            }
        }
        let node_id = read_var_int::<u16>(&mut data_reader).map_err(|_| EntityParserError::BadData("can't create node id from received bytes"))?;
        let slots_start_idx = read_var_int::<u8>(&mut data_reader).map_err(|_| EntityParserError::BadData("can't create slots idx from received bytes"))?;
        if slots_start_idx as usize >= STATE_SLOTS_SIZE {
            return Err(EntityParserError::BadData("slots index out of bounds"));
        }

        if data_reader.is_empty() {
            return Err(EntityParserError::BadData("empty slots"));
        }

        let mut lag_slots = LinkStateSlots::<u16>::default();
        let mut drop_slots = LinkStateSlots::<u16>::default();
        let mut kb_recv_slots = LinkStateSlots::<u32>::default();
        let mut i = slots_start_idx as usize;
        while !data_reader.is_empty() {
            lag_slots[i] =
                Some(read_var_int::<u16>(&mut data_reader).map_err(|_| EntityParserError::BadData("can't create log_slots sample from received bytes"))?);
            drop_slots[i] =
                Some(read_var_int::<u16>(&mut data_reader).map_err(|_| EntityParserError::BadData("can't create drop_slots sample from received bytes"))?);
            kb_recv_slots[i] =
                Some(read_var_int::<u32>(&mut data_reader).map_err(|_| EntityParserError::BadData("cant create kb_recv_slots sample from received bytes"))?);
            i = (i + 1) % STATE_SLOTS_SIZE;
        }
        Ok(Entity::LinkState(LinkStateData {
            node_id,
            starting_point: slots_start_idx,
            lag_slots,
            drop_slots,
            kb_recv_slots,
        }))
    }

    #[cfg(test)]
    mod tests {
        use cjdns_keys::CJDNSKeysApi;

        use super::*;

        fn decode_hex<T: AsRef<[u8]>>(hex: T) -> Vec<u8> {
            hex::decode(hex).expect("invalid hex string")
        }

        #[test]
        fn test_parse_header() {
            let keys_api = CJDNSKeysApi::new().expect("keys API init failed");
            let rand_data = vec![0; 72];
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
                header_bytes.extend_from_slice(&keys.public_key);
                header_bytes.extend_from_slice(&keys.ip6);
                header_bytes.extend_from_slice(random_timestamp);
                header_bytes
            };

            let parsed_header = parse_header(&header_bytes).expect("parse failed");
            assert_eq!(
                parsed_header,
                AnnouncementHeader {
                    signature: hex::encode(random_signature),
                    pub_signing_key: hex::encode(&*keys.public_key),
                    snode_ip: keys.ip6,
                    timestamp: ann_timestamp,
                    version,
                    is_reset
                }
            )
        }

        #[test]
        fn test_parse_header_invalid_len() {
            let invalid_header_lengths = (0..=255).filter(|&x| x != HEADER_SIZE);
            for len in invalid_header_lengths {
                let random_header_bytes = vec![0; len];
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
            let header_bytes = decode_hex(valid_hexed_header);
            let parsed_announcement = parser::parse(AnnouncementPacket::try_new(header_bytes).expect("invalid bytes len")).expect("invalid ann data");
            assert_eq!(parsed_announcement.entities, vec![]);
        }

        #[test]
        fn test_parse_entities() {
            let invalid_data = [
                // zero length entity
                decode_hex("00123123132412"),
                decode_hex("02050001"),
                decode_hex("02050100"),
                // no type
                decode_hex("02"),
                // invalid encoded length
                decode_hex("0305"),
                decode_hex("02050302"),
                // invalid data size for entities
                decode_hex("030201"),     // version entity len should be 4
                decode_hex("0501000220"), // peer entity len should be 32
                // mixing valid and invalid
                decode_hex("030507006114458100"), // 0305 and valid encoding entity
                decode_hex("0204020012"),         // 02 and valid version entity
                decode_hex("20200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015"), // 20 and valid peer entity
            ];
            for data in invalid_data.iter() {
                assert!(parse_entities(data).is_err());
            }

            let valid_tests = vec![
                // no entities passed
                (decode_hex(""), vec![]),
                (
                    decode_hex("200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000003"),
                    vec![Entity::Peer(PeerData {
                        ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                        label: Some(RoutingLabel::<u32>::try_new(3).expect("zero label bits")),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0,
                    })],
                ),
                (
                    decode_hex("04020002200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000020"),
                    vec![
                        Entity::NodeProtocolVersion(2),
                        Entity::Peer(PeerData {
                            ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                            label: Some(RoutingLabel::<u32>::try_new(32).expect("zero label bits")),
                            mtu: 0,
                            peer_num: 65535,
                            unused: 4294967295,
                            encoding_form_number: 0,
                            flags: 0,
                        }),
                    ],
                ),
                (
                    // with some pads
                    decode_hex("0402000201010101200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000013"),
                    vec![
                        Entity::NodeProtocolVersion(2),
                        Entity::Peer(PeerData {
                            ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                            label: Some(RoutingLabel::<u32>::try_new(19).expect("zero label bits")),
                            mtu: 0,
                            peer_num: 65535,
                            unused: 4294967295,
                            encoding_form_number: 0,
                            flags: 0,
                        }),
                    ],
                ),
                (
                    // with unrecognised entities at the beginning and at the end
                    decode_hex("020701200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000003030510"),
                    vec![Entity::Peer(PeerData {
                        ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                        label: Some(RoutingLabel::<u32>::try_new(3).expect("zero label bits")),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0,
                    })],
                ),
                (
                    // all of them are unrecognised
                    decode_hex("03100102050504020304"),
                    vec![],
                ),
            ];
            for (test_bytes, res) in valid_tests.iter() {
                let parsed_entity = parse_entities(test_bytes).expect("invalid entity passed");
                assert_eq!(parsed_entity, *res);
            }
        }

        #[test]
        fn test_multiple_peers() {
            let multiple_peer_entity_hex = {
                let peer_data_hex = "200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015";
                format!("{}{}{}", peer_data_hex, peer_data_hex, peer_data_hex)
            };
            let entities_data_vec = decode_hex(multiple_peer_entity_hex);

            let parsed_peer = Entity::Peer(PeerData {
                ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").expect("failed ip6 creation"),
                label: Some(RoutingLabel::<u32>::try_new(21).expect("zero label bits")),
                mtu: 0,
                peer_num: 65535,
                unused: 4294967295,
                encoding_form_number: 0,
                flags: 0,
            });
            let parsed_entities = parse_entities(&entities_data_vec).expect("parsing entities failed");

            assert_eq!(parsed_entities, vec![parsed_peer; 3]);
        }

        #[test]
        fn test_parse_link_state_base() {
            let test_bytes = decode_hex("2003060000000000000410130001120002130002130000140003120001130001");
            let res = parse_entities(&test_bytes).expect("invalid entity");
            assert_eq!(
                res,
                vec![Entity::LinkState(LinkStateData {
                    node_id: 4,
                    starting_point: 16,
                    lag_slots: [
                        Some(19),
                        Some(19),
                        Some(20),
                        Some(18),
                        Some(19),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(19),
                        Some(18)
                    ],
                    drop_slots: [
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(0),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(0),
                        Some(0)
                    ],
                    kb_recv_slots: [
                        Some(2),
                        Some(0),
                        Some(3),
                        Some(1),
                        Some(1),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(1),
                        Some(2)
                    ]
                })]
            )
        }

        #[test]
        fn test_parse_link_state() {
            let invalid_data = [
                // no pads
                decode_hex("0203"),
                // invalid pads (non zero pad in data)
                decode_hex("07030400000001"),
                // bad node id data
                decode_hex("080300fe01020304"),
                // bad slots starting idx data
                decode_hex("090300fd0102fd0102"),
                // out of bounds starting idx
                decode_hex("050300fafa"),
                // empty slots
                decode_hex("050300fa0a"),
                // inconsistent slots data: some slots have more samples data
                decode_hex("0b0300fa0f010203fd0102"),
                // bad lag slot data
                decode_hex("120300fa0f010203040506fe010203040102"),
                // bad drop slot data
                decode_hex("130300fa0f010203040506fd0102fe03040102"),
                // bad kb_recv slot data
                decode_hex("10030001010203ff1122334455667788"),
                // insufficient data
                // not enough ff bytes
                decode_hex("0f0300fa0f0102ff01020304050607"),
                // can't create log slot
                decode_hex("070300fa0ffd01"),
                // can't create log slot
                decode_hex("090300fa0ffe010203"),
            ];
            for data in invalid_data.iter() {
                assert!(parse_entities(data).is_err())
            }
        }

        #[test]
        fn test_link_state_valid() {
            let valid_cases = [
                // minimum valid
                decode_hex("0803000102030405"),
                // var ints
                decode_hex("2d0300fd00af00fdaa01fdaa01ff00000000556677887788ff0000000011223344fdaa0101fe03040506110f78"),
                // with some pads
                decode_hex("0d030500000000000a0a0a0a0a"),
            ];
            for data in valid_cases.iter() {
                assert!(parse_entities(data).is_ok());
            }
        }
    }
}
