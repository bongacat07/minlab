use std::net::Ipv4Addr;

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        sum += (rem[0] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}
pub fn compute_ipv4_checksum(header: &[u8]) -> u16 {
    let mut buf = [0u8; 60];
    let len = header.len();
    buf[..len].copy_from_slice(header);
    buf[10] = 0;
    buf[11] = 0;
    checksum(&buf[..len])
}

pub fn compute_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp_segment.len());

    buf.extend_from_slice(&src_ip.octets());
    buf.extend_from_slice(&dst_ip.octets());
    buf.push(0);
    buf.push(6);
    buf.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());

    buf.extend_from_slice(tcp_segment);

    let checksum_offset = 12 + 16;
    buf[checksum_offset] = 0;
    buf[checksum_offset + 1] = 0;

    checksum(&buf)
}
