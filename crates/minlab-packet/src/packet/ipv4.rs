use std::fmt;
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

fn ipv4_checksum(header_bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < header_bytes.len() {
        let word = if i + 1 < header_bytes.len() {
            u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]])
        } else {
            u16::from_be_bytes([header_bytes[i], 0])
        };

        sum += word as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

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
    let expected_checksum = ipv4_checksum(&buf[0..header_len]);
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
