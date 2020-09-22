//! Msgpack-encodable message that is sent between cjdns supernodes.

use cjdns_ann::AnnHash;

use crate::peer::AnnData;

/// Message consisting of an unique reply ID and message data.
/// ID can be zero if no reply is required.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message(pub u64, pub MessageData);

#[allow(non_camel_case_types)] // To keep naming consistent with JS code
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MessageData { //TODO proper enum with serde annotations
    HELLO(u32), OLLEH(u32), PING, ACK, GET_DATA(AnnHash), DATA(AnnData), INV(Vec<AnnHash>)
}

impl Message {
    pub fn decode_msgpack(_bytes: &[u8]) -> Self {
        todo!()
    }

    pub fn encode_msgpack(&self) -> Vec<u8> {
        todo!()
    }
}

impl MessageData {
    /// Create MessageData instance.
    ///
    /// This method is not part of public API, though it need to be `pub` so it can be used with the `msg!` macro.
    #[inline]
    pub fn new(type_str: &str, int_arg: Option<u32>, hash_arr_arg: Option<&[AnnHash]>, data_arg: Option<AnnData>) -> Option<Self> {
        let res = match (type_str, int_arg, hash_arr_arg, data_arg) {
            ("HELLO", Some(version), None, None) => MessageData::HELLO(version),
            ("OLLEH", Some(version), None, None) => MessageData::OLLEH(version),
            ("PING", None, None, None) => MessageData::PING,
            ("ACK", None, None, None) => MessageData::ACK,
            ("GET_DATA", None, Some(hashes), None) if hashes.len() == 1 => MessageData::GET_DATA(hashes[0].clone()),
            ("DATA", None, None, Some(data)) => MessageData::DATA(data.clone()),
            ("INV", None, Some(hashes), None) => MessageData::INV(hashes.iter().cloned().collect()),
            _ => return None
        };
        Some(res)
    }
}

#[macro_export]
macro_rules! msg {
    ( $id:expr, $msgtype:literal ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, None, None, None).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal, $int:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, Some($int), None, None).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal | hash = $arr:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, None, Some(&[$arr]), None).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal | data = $bytes:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, None, None, Some($bytes)).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal, $int:expr => hashes = $arrs:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, Some($int), Some($arrs), None).expect("bad message literal"))
    }};
}

#[cfg(test)]
mod tests {
    use cjdns_ann::AnnHash;

    use super::Message;

    macro_rules! hex {
        ( $hex:literal ) => {
            &hex::decode($hex).expect("bad hex value")
        }
    }

    macro_rules! hash {
        ( $( $bytes:expr ),* ) => {
            AnnHash(vec![$( $bytes ),*])
        }
    }

    #[test]
    fn test_message() {
        let version = 0x42;

        let test = |msg: Message| {
            let bytes = msg.encode_msgpack();
            let decoded = Message::decode_msgpack(&bytes);
            assert_eq!(msg, decoded, "msgpack encode/decode test failed for message {:?}", msg);
        };

        test(msg![0, "HELLO", version]);
        test(msg![0, "OLLEH", version]);
        test(msg![1, "PING"]);
        test(msg![1, "ACK"]);
        test(msg![2, "GET_DATA" | hash = hash![0x11, 0x12, 0x13, 0x14]]);
        test(msg![2, "DATA" | data = vec![0x11, 0x12, 0x13, 0x14]]);
        test(msg![0, "INV", 0 => hashes = &[ hash![1, 2, 3], hash![4, 5, 6], hash![7, 8, 9] ]]);
    }

    #[test]
    fn test_message_decode() {
        let test = |msg: Message, bytes: &[u8]| {
            let decoded = Message::decode_msgpack(bytes);
            assert_eq!(msg, decoded, "msgpack decode test failed for message {:?}", msg);
        };

        // TODO Use this JavaScript code to produce the bytes for the test.
        // ```javascript
        // const dumpRawBytes = function (msg) {
        //     bytes = msgpack.encode(msg);
        //     console.log(bytes);
        // };
        // dumpRawBytes([0, 'HELLO', 42]);
        // dumpRawBytes([0, 'OLLEH', 42]);
        // dumpRawBytes([1, 'PING']);
        // dumpRawBytes([1, 'ACK']);
        // dumpRawBytes([2, 'GET_DATA', new Buffer('A1B2C3D4', 'hex')]);
        // dumpRawBytes([2, 'DATA', new Buffer('A1B2C3D4', 'hex')]]);
        // dumpRawBytes([0, 'INV', 0, [ new Buffer('A1B2C3D4', 'hex'), new Buffer('E5F60102', 'hex'), new Buffer('12345678', 'hex') ] ]);
        // ```

        test(msg![0, "HELLO", 42], hex!("todo"));
        test(msg![0, "OLLEH", 42], hex!("todo"));
        test(msg![1, "PING"], hex!("todo"));
        test(msg![1, "ACK"], hex!("todo"));
        test(msg![2, "GET_DATA" | hash = hash![0xA1, 0xB2, 0xC3, 0xD4]], hex!("todo"));
        test(msg![2, "DATA" | data = vec![0xA1, 0xB2, 0xC3, 0xD4]], hex!("todo"));
        test(msg![0, "INV", 0 => hashes = &[ hash![0xA1, 0xB2, 0xC3, 0xD4], hash![0xE5, 0xF6, 0x01, 0x02], hash![0x12, 0x34, 0x56, 0x78] ]], hex!("todo"));
    }
}