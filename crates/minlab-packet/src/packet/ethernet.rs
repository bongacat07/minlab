use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn octets(self) -> [u8; 6] {
        self.0
    }

    pub fn parse(s: &str) -> Result<Self, MacParseError> {
        let parts: Vec<&str> = s.split([':', '-']).collect();

        if parts.len() != 6 {
            return Err(MacParseError(s.to_string()));
        }

        let mut mac = [0u8; 6];

        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(MacParseError(s.to_string()));
            }

            mac[i] = u8::from_str_radix(part, 16).map_err(|_| MacParseError(s.to_string()))?;
        }

        Ok(Self(mac))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

#[derive(Debug)]
pub struct MacParseError(String);

impl fmt::Display for MacParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid MAC address: {}", self.0)
    }
}

impl std::error::Error for MacParseError {}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ether_type: EtherType,
    pub payload: Vec<u8>,
}

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
