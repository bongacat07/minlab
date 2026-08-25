use crate::packet::ethernet::mac::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Other(u16),
}

impl EtherType {
    pub const IPV4: Self = Self::Ipv4;
    pub const ARP: Self = Self::Arp;
    pub const IPV6: Self = Self::Ipv6;

    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            other => Self::Other(other),
        }
    }

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86dd,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ether_type: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn new() -> Self {
        Self {
            dst_mac: MacAddr::new([0; 6]),
            src_mac: MacAddr::new([0; 6]),
            ether_type: EtherType::Other(0),
            payload: Vec::new(),
        }
    }

    pub fn dst_mac(mut self, mac: MacAddr) -> Self {
        self.dst_mac = mac;
        self
    }

    pub fn src_mac(mut self, mac: MacAddr) -> Self {
        self.src_mac = mac;
        self
    }

    pub fn eth_type(mut self, ether_type: EtherType) -> Self {
        self.ether_type = ether_type;
        self
    }

    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    pub fn set_dst_mac(&mut self, mac: MacAddr) {
        self.dst_mac = mac;
    }

    pub fn set_src_mac(&mut self, mac: MacAddr) {
        self.src_mac = mac;
    }

    pub fn set_eth_type(&mut self, ether_type: EtherType) {
        self.ether_type = ether_type;
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        self.payload = payload.to_vec();
    }
}

impl Default for EthernetFrame {
    fn default() -> Self {
        Self::new()
    }
}

pub fn serialize_ethernet(frame: &EthernetFrame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + frame.payload.len());

    buf.extend_from_slice(&frame.dst_mac.octets());
    buf.extend_from_slice(&frame.src_mac.octets());
    buf.extend_from_slice(&frame.ether_type.as_u16().to_be_bytes());
    buf.extend_from_slice(&frame.payload);

    buf
}
