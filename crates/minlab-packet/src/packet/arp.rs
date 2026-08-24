use tun_tap::Iface;

const MY_MAC: [u8; 6] = [0x06, 0x09, 0x04, 0x02, 0x00, 0x0a];
const MY_IP: [u8; 4] = [11, 0, 0, 2];
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_size: u8,
    pub protocol_size: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

pub fn parse_arp(buf: &[u8]) -> Option<ArpPacket> {
    if buf.len() < 28 {
        return None;
    }
    Some(ArpPacket {
        hardware_type: u16::from_be_bytes([buf[0], buf[1]]),
        protocol_type: u16::from_be_bytes([buf[2], buf[3]]),
        hardware_size: buf[4],
        protocol_size: buf[5],
        opcode: u16::from_be_bytes([buf[6], buf[7]]),
        sender_mac: buf[8..14].try_into().unwrap(),
        sender_ip: buf[14..18].try_into().unwrap(),
        target_mac: buf[18..24].try_into().unwrap(),
        target_ip: buf[24..28].try_into().unwrap(),
    })
}

pub fn serialise_arp(x: &ArpPacket) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    buf.extend_from_slice(&x.hardware_type.to_be_bytes());
    buf.extend_from_slice(&x.protocol_type.to_be_bytes());
    buf.push(x.hardware_size);
    buf.push(x.protocol_size);
    buf.extend_from_slice(&x.opcode.to_be_bytes());
    buf.extend_from_slice(&x.sender_mac);
    buf.extend_from_slice(&x.sender_ip);
    buf.extend_from_slice(&x.target_mac);
    buf.extend_from_slice(&x.target_ip);

    buf
}

pub fn send_arp_reply(iface: &Iface, req: &ArpPacket) {
    let mut buf = Vec::with_capacity(42);

    buf.extend_from_slice(&req.sender_mac);
    buf.extend_from_slice(&MY_MAC);
    buf.extend_from_slice(&0x0806u16.to_be_bytes());
    buf.extend_from_slice(&req.hardware_type.to_be_bytes());
    buf.extend_from_slice(&req.protocol_type.to_be_bytes());
    buf.push(req.hardware_size);
    buf.push(req.protocol_size);
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&MY_MAC);
    buf.extend_from_slice(&MY_IP);
    buf.extend_from_slice(&req.sender_mac);
    buf.extend_from_slice(&req.sender_ip);
    let _ = iface.send(&buf);
}
