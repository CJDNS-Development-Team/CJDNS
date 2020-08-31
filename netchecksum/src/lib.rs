//! The 1s complement checksum used by TCP, UDP and ICMP.

use std::convert::TryInto;

/// Sum all words (16 bit chunks) in the given data.
/// Each word is treated as big endian.
fn sum_be_words(data: &[u8]) -> u32 {
    if data.len() == 0 {
        return 0;
    }
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0_u32;
    let mut hbit = 0_u32;
    while cur_data.len() >= 2 {
        // It's safe to unwrap because we verified there are at least 2 bytes
        let word = cur_data[0..2].try_into().unwrap();
        sum += u16::from_be_bytes(word) as u32;
        if sum > 0x7fffffff {
            hbit ^= 1;
            sum &= 0x7fffffff;
        }
        cur_data = &cur_data[2..];
    }

    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum |= hbit << 31;

    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

pub fn cksum_raw(buf: &[u8]) -> u16 {
    let sum = sum_be_words(buf);
    finalize_checksum(sum)
}

pub fn cksum_udp4(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, content: &[u8]) -> Result<u16, ()> {
    let src_port = src_port.to_be_bytes();
    let dst_port = dst_port.to_be_bytes();

    // length includes the length of the udp header
    if 8 + content.len() > 0xFFFF {
        return Err(()); // it is impossible to make a UDP packet of length > 65535
    }
    let length = ((8 + content.len()) as u16).to_be_bytes();

    let mut data = Vec::with_capacity(4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + content.len());
    data.extend_from_slice(&src_ip);
    data.extend_from_slice(&dst_ip);
    data.extend_from_slice(&[0, 17]);
    data.extend_from_slice(&length);
    data.extend_from_slice(&src_port);
    data.extend_from_slice(&dst_port);
    data.extend_from_slice(&length);
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(content);

    Ok(cksum_raw(&data))
}

#[test]
fn test_raw() {
    let hexbuf = |s: &str| hex::decode(s).expect("bad test data");

    /*let fill = |len: usize, filler: &[u8]| {
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            buf.extend_from_slice(filler);
        }
        buf.truncate(len);
        buf
    };*/

    let cases = [
        (
            hexbuf("fce5de17cbdec87b528905568b83c9c8fc0000000000000000000000000000010000001900000011b4a9003500190000e4e4010000010000000000000000020001"),
            0x4972
        ),
        // Validate that even when the int rolls over it still works.
        /*(fill(40000, b"This_is_a_test__"), 0x62d0),
        (fill(50000, b"This_is_a_test__"), 0x7c44),*/
        (hexbuf("45000054ccf3000040010000c0a80001c0a8000b"), 0x2c59),
        (hexbuf("45000034fa4d400040064b8d0a4206015cde87c8"), 0x0000),
        (hexbuf("45000034fa4d4000400600000a4206015cde87c8"), 0x4b8d),
    ];
    for &(ref buf, sum) in &cases {
        assert_eq!(cksum_raw(buf), sum, "{:x} vs {:x}: failed for {:?}", cksum_raw(buf), sum, hex::encode(buf));
    }
}

#[test]
fn test_udp4() {
    let src = [0xc0, 0xa8, 0x01, 0x91];
    let dst = [0xc0, 0xa8, 0x01, 0x01];
    let content = &[
        0xfe, 0x8d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01
    ];
    assert_eq!(cksum_udp4(src, dst, 0xf970, 0x0035, content), Ok(0x6fd6));
}