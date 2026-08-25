use crate::packet::tcp::flags::*;
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

    pub fn set_src_port(&mut self, port: u16) {
        self.header.src_port = port;
    }
    pub fn set_dst_port(&mut self, port: u16) {
        self.header.dst_port = port;
    }
    pub fn set_seq_num(&mut self, num: u32) {
        self.header.seq_num = num;
    }
    pub fn set_ack_num(&mut self, num: u32) {
        self.header.ack_num = num;
    }
    pub fn set_data_offset(&mut self, offset: u8) {
        self.header.data_offset = offset;
    }
    pub fn set_flags(&mut self, flags: u16) {
        self.header.flags = flags;
    }
    pub fn set_window(&mut self, window: u16) {
        self.header.window = window;
    }
    pub fn set_checksum(&mut self, checksum: u16) {
        self.header.checksum = checksum;
    }
    pub fn set_urgent_ptr(&mut self, ptr: u16) {
        self.header.urgent_ptr = ptr;
    }
    pub fn set_payload(&mut self, data: Vec<u8>) {
        self.payload = data;
    }

    pub fn set_with_flag(&mut self, flag: u16) {
        self.header.flags |= flag;
    }
    pub fn set_without_flag(&mut self, flag: u16) {
        self.header.flags &= !flag;
    }
    pub fn set_toggle_flag(&mut self, flag: u16) {
        self.header.flags ^= flag;
    }
    pub fn set_clear_flags(&mut self) {
        self.header.flags = 0;
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
