use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Protocol {
    pub const TCP: Self = Self::Tcp;
    pub const UDP: Self = Self::Udp;
    pub const ICMP: Self = Self::Icmp;

    pub const fn from_u8(value: u8) -> Self {
        match value {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            other => Self::Other(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Flags {
    Reserved,
    MoreFragments,
    DontFragment,
    Other(u8),
}

impl Ipv4Flags {
    pub const RESERVED: Self = Self::Reserved;
    pub const DONT_FRAGMENT: Self = Self::DontFragment;
    pub const MORE_FRAGMENTS: Self = Self::MoreFragments;

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0b000 => Self::Reserved,
            0b010 => Self::DontFragment,
            0b001 => Self::MoreFragments,
            other => Self::Other(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Reserved => 0b000,
            Self::DontFragment => 0b010,
            Self::MoreFragments => 0b001,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4HeaderFields {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: Ipv4Flags,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

#[derive(Debug)]
pub struct Ipv4Header {
    pub fields: Ipv4HeaderFields,
    pub header_checksum: u16,
}

#[derive(Debug)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new() -> Self {
        Ipv4Packet {
            header: Ipv4Header {
                fields: Ipv4HeaderFields {
                    version: 4,
                    ihl: 5,
                    tos: 0,
                    total_length: 20,
                    identification: 0,
                    flags: Ipv4Flags::Reserved,
                    fragment_offset: 0,
                    ttl: 64,
                    protocol: Protocol::Other(0),
                    source: Ipv4Addr::new(0, 0, 0, 0),
                    destination: Ipv4Addr::new(0, 0, 0, 0),
                },
                header_checksum: 0,
            },
            payload: Vec::new(),
        }
    }

    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        let header_len = (self.header.fields.ihl as u16) * 4;
        self.header.fields.total_length = header_len + self.payload.len() as u16;
        self
    }

    pub fn version(mut self, version: u8) -> Self {
        self.header.fields.version = version;
        self
    }

    pub fn ihl(mut self, ihl: u8) -> Self {
        self.header.fields.ihl = ihl;
        let header_len = (ihl as u16) * 4;
        self.header.fields.total_length = header_len + self.payload.len() as u16;
        self
    }

    pub fn tos(mut self, tos: u8) -> Self {
        self.header.fields.tos = tos;
        self
    }

    pub fn total_length(mut self, total_length: u16) -> Self {
        self.header.fields.total_length = total_length;
        self
    }

    pub fn identification(mut self, id: u16) -> Self {
        self.header.fields.identification = id;
        self
    }

    pub fn flags(mut self, flags: Ipv4Flags) -> Self {
        self.header.fields.flags = flags;
        self
    }

    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.header.fields.fragment_offset = offset;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.header.fields.ttl = ttl;
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.header.fields.protocol = protocol;
        self
    }

    pub fn header_checksum(mut self, checksum: u16) -> Self {
        self.header.header_checksum = checksum;
        self
    }

    pub fn set_version(&mut self, version: u8) {
        self.header.fields.version = version;
    }

    pub fn set_ihl(&mut self, ihl: u8) {
        self.header.fields.ihl = ihl;
        let header_len = (ihl as u16) * 4;
        self.header.fields.total_length = header_len + self.payload.len() as u16;
    }

    pub fn set_tos(&mut self, tos: u8) {
        self.header.fields.tos = tos;
    }

    pub fn set_total_length(&mut self, total_length: u16) {
        self.header.fields.total_length = total_length;
    }

    pub fn set_identification(&mut self, id: u16) {
        self.header.fields.identification = id;
    }

    pub fn set_flags(&mut self, flags: Ipv4Flags) {
        self.header.fields.flags = flags;
    }

    pub fn set_fragment_offset(&mut self, offset: u16) {
        self.header.fields.fragment_offset = offset;
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.header.fields.ttl = ttl;
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.header.fields.protocol = protocol;
    }

    pub fn set_header_checksum(&mut self, checksum: u16) {
        self.header.header_checksum = checksum;
    }

    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.header.fields.source = source;
    }

    pub fn set_destination(&mut self, destination: Ipv4Addr) {
        self.header.fields.destination = destination;
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        self.payload = payload.to_vec();

        let header_len = (self.header.fields.ihl as u16) * 4;

        self.header.fields.total_length = header_len + self.payload.len() as u16;
    }
}

impl Default for Ipv4Packet {
    fn default() -> Self {
        Self::new()
    }
}

pub fn serialise_ipv4(x: &Ipv4Packet) -> Vec<u8> {
    let mut buf = Vec::new();
    let f = &x.header.fields;

    buf.push((f.version << 4) | (f.ihl & 0x0f));
    buf.push(f.tos);
    buf.extend_from_slice(&f.total_length.to_be_bytes());
    buf.extend_from_slice(&f.identification.to_be_bytes());

    let flags_and_offset: u16 =
        ((f.flags.as_u8() as u16 & 0x07) << 13) | (f.fragment_offset & 0x1fff);

    buf.extend_from_slice(&flags_and_offset.to_be_bytes());
    buf.push(f.ttl);
    buf.push(f.protocol.as_u8());
    buf.extend_from_slice(&x.header.header_checksum.to_be_bytes());
    buf.extend_from_slice(&f.source.octets());
    buf.extend_from_slice(&f.destination.octets());
    buf.extend_from_slice(&x.payload);

    buf
}

pub fn serialise_ipv4_header(x: &Ipv4Header) -> Vec<u8> {
    let mut buf = Vec::new();
    let f = &x.fields;

    buf.push((f.version << 4) | (f.ihl & 0x0f));
    buf.push(f.tos);
    buf.extend_from_slice(&f.total_length.to_be_bytes());
    buf.extend_from_slice(&f.identification.to_be_bytes());

    let flags_and_offset: u16 =
        ((f.flags.as_u8() as u16 & 0x07) << 13) | (f.fragment_offset & 0x1fff);

    buf.extend_from_slice(&flags_and_offset.to_be_bytes());
    buf.push(f.ttl);
    buf.push(f.protocol.as_u8());
    buf.extend_from_slice(&x.header_checksum.to_be_bytes());
    buf.extend_from_slice(&f.source.octets());
    buf.extend_from_slice(&f.destination.octets());

    buf
}
