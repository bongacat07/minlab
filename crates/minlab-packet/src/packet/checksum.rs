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
