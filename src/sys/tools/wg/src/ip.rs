use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Complete inner IP packets only. Checksums remain the IP stack's job.
pub(crate) fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 15) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20 || header_len > total_len || total_len != packet.len() {
                return None;
            }
            Some((
                Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?).into(),
                Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?).into(),
            ))
        }
        6 if packet.len() >= 40 => {
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if payload_len + 40 != packet.len() {
                return None;
            }
            Some((
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).into(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).into(),
            ))
        }
        _ => None,
    }
}
