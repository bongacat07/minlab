use crate::packet::checksum::*;
use crate::packet::ipv4::ipv4_packet::*;
use std::fmt;
use std::net::Ipv4Addr;
#[derive(Debug)]
pub struct BuffTooShort {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct IHLTooSmall {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct BuffShorterThanHeader {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct TotalLengthSmallerThanHeader {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub struct ChecksumMismatch {
    pub expected: u16,
    pub recieved: u16,
}

#[derive(Debug)]
pub struct UnsupportedVersion {
    pub recieved: u8,
}

#[derive(Debug)]
pub struct TotalLengthExceedsBuffer {
    pub expected: usize,
    pub recieved: usize,
}

#[derive(Debug)]
pub enum IpV4ParseError {
    BuffTooShort(BuffTooShort),
    UnsupportedVersion(UnsupportedVersion),
    IHLTooSmall(IHLTooSmall),
    BuffShorterThanHeader(BuffShorterThanHeader),
    TotalLengthSmallerThanHeader(TotalLengthSmallerThanHeader),
    TotalLengthExceedsBuffer(TotalLengthExceedsBuffer),
    ChecksumMismatch(ChecksumMismatch),
}

impl fmt::Display for IpV4ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuffTooShort(e) => write!(
                f,
                "IPv4 packet too short: expected at least {} bytes, got {}",
                e.expected, e.recieved
            ),
            Self::UnsupportedVersion(e) => {
                write!(f, "unsupported IP version: {}", e.recieved)
            }
            Self::IHLTooSmall(e) => write!(
                f,
                "IHL too small: expected at least {}, got {}",
                e.expected, e.recieved
            ),
            Self::BuffShorterThanHeader(e) => write!(
                f,
                "buffer shorter than declared header: expected at least {} bytes, got {}",
                e.expected, e.recieved
            ),
            Self::TotalLengthSmallerThanHeader(e) => write!(
                f,
                "total length smaller than header: expected at least {} bytes, got {}",
                e.expected, e.recieved
            ),
            Self::TotalLengthExceedsBuffer(e) => write!(
                f,
                "total length exceeds buffer: expected at most {} bytes, got {}",
                e.expected, e.recieved
            ),
            Self::ChecksumMismatch(e) => write!(
                f,
                "header checksum mismatch: expected {:#06x}, got {:#06x}",
                e.expected, e.recieved
            ),
        }
    }
}

impl std::error::Error for IpV4ParseError {}

pub fn parse_ipv4(buf: &[u8]) -> Result<Ipv4Packet, IpV4ParseError> {
    if buf.len() < 20 {
        return Err(IpV4ParseError::BuffTooShort(BuffTooShort {
            expected: 20,
            recieved: buf.len(),
        }));
    }

    let version = buf[0] >> 4;
    let ihl = buf[0] & 0x0f;

    if version != 4 {
        return Err(IpV4ParseError::UnsupportedVersion(UnsupportedVersion {
            recieved: version,
        }));
    }

    if ihl < 5 {
        return Err(IpV4ParseError::IHLTooSmall(IHLTooSmall {
            expected: 5,
            recieved: ihl as usize,
        }));
    }

    let header_len = (ihl as usize) * 4;

    if buf.len() < header_len {
        return Err(IpV4ParseError::BuffShorterThanHeader(
            BuffShorterThanHeader {
                expected: header_len,
                recieved: buf.len(),
            },
        ));
    }

    let total_length = u16::from_be_bytes([buf[2], buf[3]]);

    if total_length < header_len as u16 {
        return Err(IpV4ParseError::TotalLengthSmallerThanHeader(
            TotalLengthSmallerThanHeader {
                expected: header_len,
                recieved: total_length as usize,
            },
        ));
    }

    if total_length as usize > buf.len() {
        return Err(IpV4ParseError::TotalLengthExceedsBuffer(
            TotalLengthExceedsBuffer {
                expected: buf.len(),
                recieved: total_length as usize,
            },
        ));
    }

    let received_checksum = u16::from_be_bytes([buf[10], buf[11]]);
    let expected_checksum = compute_ipv4_checksum(&buf[0..header_len]);
    if received_checksum != expected_checksum {
        return Err(IpV4ParseError::ChecksumMismatch(ChecksumMismatch {
            expected: expected_checksum,
            recieved: received_checksum,
        }));
    }
    let flags = Ipv4Flags::from_u8((buf[6] >> 5) & 0x07);
    let fragment_offset = (((buf[6] as u16) & 0x1f) << 8) | buf[7] as u16;

    let payload = buf[header_len..total_length as usize].to_vec();

    Ok(Ipv4Packet {
        header: Ipv4Header {
            fields: Ipv4HeaderFields {
                version,
                ihl,
                tos: buf[1],
                total_length,
                identification: u16::from_be_bytes([buf[4], buf[5]]),
                flags,
                fragment_offset,
                ttl: buf[8],
                protocol: Protocol::from_u8(buf[9]),
                source: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
                destination: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            },
            header_checksum: received_checksum,
        },
        payload,
    })
}
