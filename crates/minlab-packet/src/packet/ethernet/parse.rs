use crate::packet::ethernet::eth_frame::*;
use crate::packet::ethernet::mac::*;
use std::fmt;
#[derive(Debug)]
pub struct EthernetParseError {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for EthernetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ethernet frame too short: expected at least {} bytes, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for EthernetParseError {}

pub fn parse_ethernet_frame(buf: &[u8]) -> Result<EthernetFrame, EthernetParseError> {
    if buf.len() < 14 {
        return Err(EthernetParseError {
            expected: 14,
            actual: buf.len(),
        });
    }

    Ok(EthernetFrame {
        dst_mac: MacAddr::new(buf[0..6].try_into().unwrap()),
        src_mac: MacAddr::new(buf[6..12].try_into().unwrap()),
        ether_type: EtherType::from_u16(u16::from_be_bytes([buf[12], buf[13]])),
        payload: buf[14..].to_vec(),
    })
}
