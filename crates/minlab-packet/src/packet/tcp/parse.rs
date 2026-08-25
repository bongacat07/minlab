use crate::packet::checksum::compute_tcp_checksum;
use crate::packet::tcp::tcp_packet::*;
use std::fmt;
use std::net::Ipv4Addr;
#[derive(Debug)]
pub struct BuffTooShort {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct DataOffsetTooSmall {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct BuffShorterThanHeader {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct ChecksumMismatch {
    pub expected: u16,
    pub recieved: u16,
}

#[derive(Debug)]
pub enum TCPParseError {
    BuffTooShort(BuffTooShort),
    DataOffsetTooSmall(DataOffsetTooSmall),
    BuffShorterThanHeader(BuffShorterThanHeader),
    ChecksumMismatch(ChecksumMismatch),
}

impl fmt::Display for TCPParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuffTooShort(e) => write!(
                f,
                "TCP segment too short: expected at least {} bytes, got {}",
                e.expected, e.recieved
            ),
            Self::DataOffsetTooSmall(e) => write!(
                f,
                "Data Offset too small: expected at least {}, got {}",
                e.expected, e.recieved
            ),
            Self::BuffShorterThanHeader(e) => write!(
                f,
                "buffer shorter than declared header: expected at least {} bytes, got {}",
                e.expected, e.recieved
            ),
            Self::ChecksumMismatch(e) => write!(
                f,
                "TCP checksum mismatch: expected {:#06x}, got {:#06x}",
                e.expected, e.recieved
            ),
        }
    }
}

impl std::error::Error for TCPParseError {}

pub fn parse_tcp(
    buf: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<TCPPacket, TCPParseError> {
    if buf.len() < 20 {
        return Err(TCPParseError::BuffTooShort(BuffTooShort {
            expected: 20,
            recieved: buf.len(),
        }));
    }

    let data_offset = (buf[12] >> 4) * 4;

    if data_offset < 20 {
        return Err(TCPParseError::DataOffsetTooSmall(DataOffsetTooSmall {
            expected: 20,
            recieved: data_offset as usize,
        }));
    }

    if buf.len() < data_offset as usize {
        return Err(TCPParseError::BuffShorterThanHeader(
            BuffShorterThanHeader {
                expected: data_offset as usize,
                recieved: buf.len(),
            },
        ));
    }

    let received_checksum = u16::from_be_bytes([buf[16], buf[17]]);
    let expected_checksum = compute_tcp_checksum(src_ip, dst_ip, buf);
    if received_checksum != expected_checksum {
        return Err(TCPParseError::ChecksumMismatch(ChecksumMismatch {
            expected: expected_checksum,
            recieved: received_checksum,
        }));
    }

    let header = TCPHeader {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq_num: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack_num: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        data_offset,
        flags: ((buf[12] as u16 & 0x01) << 8) | buf[13] as u16,
        window: u16::from_be_bytes([buf[14], buf[15]]),
        checksum: received_checksum,
        urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
    };

    let payload = buf[data_offset as usize..].to_vec();

    Ok(TCPPacket { header, payload })
}
