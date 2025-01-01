use ipnetwork::IpNetwork;
use smoltcp::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use std::net::{IpAddr, SocketAddr};

pub fn socket_addr_from_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let addr: IpAddr = endpoint.addr.into();
    SocketAddr::new(addr, endpoint.port)
}

pub fn ip_network_to_cidr(ip_network: &IpNetwork) -> IpCidr {
    match ip_network {
        IpNetwork::V4(network) => IpCidr::Ipv4(Ipv4Cidr::new(network.ip(), network.prefix())),
        IpNetwork::V6(network) => IpCidr::Ipv6(Ipv6Cidr::new(network.ip(), network.prefix())),
    }
}

pub fn addr_to_octets(addr: std::net::IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(addr) => {
            // Map IPv4 to IPv6.
            let mut octets = [0_u8; 16];
            let octets_4 = addr.octets();
            octets[10] = 255;
            octets[11] = 255;
            octets[12] = octets_4[0];
            octets[13] = octets_4[1];
            octets[14] = octets_4[2];
            octets[15] = octets_4[3];
            octets
        }
        IpAddr::V6(addr) => addr.octets(),
    }
}
