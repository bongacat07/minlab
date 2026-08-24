pub const FIN: u16 = 0b0000_0000_0000_0001;
pub const SYN: u16 = 0b0000_0000_0000_0010;
pub const RST: u16 = 0b0000_0000_0000_0100;
pub const PSH: u16 = 0b0000_0000_0000_1000;
pub const ACK: u16 = 0b0000_0000_0001_0000;
pub const URG: u16 = 0b0000_0000_0010_0000;
pub const ECE: u16 = 0b0000_0000_0100_0000;
pub const CWR: u16 = 0b0000_0000_1000_0000;

pub const SYN_ACK: u16 = SYN | ACK;
pub const FIN_ACK: u16 = FIN | ACK;
pub const PUSH_ACK: u16 = PSH | ACK;
pub const RST_ACK: u16 = RST | ACK;
pub const URG_ACK: u16 = URG | ACK;
pub const PSH_ACK_URG: u16 = PSH | ACK | URG;
pub const FIN_PSH_ACK: u16 = FIN | PSH | ACK;
pub const NULL_SCAN: u16 = 0b0000_0000_0000_0000;
pub const FIN_PUSH_URG: u16 = FIN | PSH | URG;
pub const SYN_FIN: u16 = SYN | FIN;
pub const SYN_RST: u16 = SYN | RST;
pub const SYN_FIN_RST: u16 = SYN | FIN | RST;
pub const ALL_FLAGS: u16 = FIN | SYN | RST | PSH | ACK | URG | ECE | CWR;
pub const ECN_SYN: u16 = SYN | ECE | CWR;
pub const ECN_SYN_ACK: u16 = SYN | ACK | ECE;
pub const RST_FIN: u16 = RST | FIN;
pub const PSH_ONLY: u16 = PSH;
pub const URG_ONLY: u16 = URG;
pub const ACK_ONLY: u16 = ACK;

#[derive(Debug, Clone, Copy)]
pub struct TCPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug)]
pub struct TCPPacket {
    pub header: TCPHeader,
    pub payload: Vec<u8>,
}

pub fn parse_tcp(buf: &[u8]) -> Option<TCPPacket> {
    if buf.len() < 20 {
        return None;
    }
    let data_offset = (buf[12] >> 4) * 4;
    if data_offset < 20 {
        return None;
    }
    if buf.len() < data_offset as usize {
        return None;
    }
    let header = TCPHeader {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq_num: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack_num: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        data_offset,
        flags: ((buf[12] as u16 & 0x01) << 8) | buf[13] as u16,
        window: u16::from_be_bytes([buf[14], buf[15]]),
        checksum: u16::from_be_bytes([buf[16], buf[17]]),
        urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
    };
    let payload = buf[data_offset as usize..].to_vec();
    Some(TCPPacket { header, payload })
}

impl TCPPacket {
    pub fn new() -> Self {
        TCPPacket {
            header: TCPHeader {
                src_port: 0,
                dst_port: 0,
                seq_num: 0,
                ack_num: 0,
                data_offset: 20,
                flags: 0,
                window: 65535,
                checksum: 0,
                urgent_ptr: 0,
            },
            payload: Vec::new(),
        }
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.header.src_port = port;
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.header.dst_port = port;
        self
    }

    pub fn seq_num(mut self, num: u32) -> Self {
        self.header.seq_num = num;
        self
    }

    pub fn window(mut self, window: u16) -> Self {
        self.header.window = window;
        self
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    pub fn ack_num(mut self, num: u32) -> Self {
        self.header.ack_num = num;
        self
    }

    pub fn urgent_ptr(mut self, ptr: u16) -> Self {
        self.header.urgent_ptr = ptr;
        self
    }

    pub fn checksum(mut self, checksum: u16) -> Self {
        self.header.checksum = checksum;
        self
    }

    pub fn data_offset(mut self, offset: u8) -> Self {
        self.header.data_offset = offset;
        self
    }

    pub fn flags(mut self, flags: u16) -> Self {
        self.header.flags = flags;
        self
    }

    pub fn with_flag(mut self, flag: u16) -> Self {
        self.header.flags |= flag;
        self
    }

    pub fn without_flag(mut self, flag: u16) -> Self {
        self.header.flags &= !flag;
        self
    }
    pub fn toggle_flag(mut self, flag: u16) -> Self {
        self.header.flags ^= flag;
        self
    }

    pub fn clear_flags(mut self) -> Self {
        self.header.flags = 0;
        self
    }

    pub fn syn(self) -> Self {
        self.with_flag(SYN)
    }
    pub fn ack(self) -> Self {
        self.with_flag(ACK)
    }
    pub fn fin(self) -> Self {
        self.with_flag(FIN)
    }
    pub fn rst(self) -> Self {
        self.with_flag(RST)
    }
    pub fn psh(self) -> Self {
        self.with_flag(PSH)
    }
    pub fn urg(self) -> Self {
        self.with_flag(URG)
    }
}

impl Default for TCPPacket {
    fn default() -> Self {
        Self::new()
    }
}

pub fn serialize_tcp_header(x: &TCPHeader) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    buf.extend_from_slice(&x.src_port.to_be_bytes());
    buf.extend_from_slice(&x.dst_port.to_be_bytes());
    buf.extend_from_slice(&x.seq_num.to_be_bytes());
    buf.extend_from_slice(&x.ack_num.to_be_bytes());

    let offset_words = x.data_offset / 4;
    let ns_bit = ((x.flags >> 8) & 0x01) as u8;

    buf.push((offset_words << 4) | ns_bit);
    buf.push((x.flags & 0xFF) as u8);
    buf.extend_from_slice(&x.window.to_be_bytes());
    buf.extend_from_slice(&x.checksum.to_be_bytes());
    buf.extend_from_slice(&x.urgent_ptr.to_be_bytes());

    buf
}
