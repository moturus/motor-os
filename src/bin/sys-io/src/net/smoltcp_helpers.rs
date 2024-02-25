use ipnetwork::IpNetwork;
use smoltcp::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use std::net::{IpAddr, SocketAddr};

pub fn socket_addr_from_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let addr: IpAddr = endpoint.addr.into();
    SocketAddr::new(addr, endpoint.port)
}

pub fn ip_network_to_cidr(ip_network: &IpNetwork) -> IpCidr {
    match ip_network {
        IpNetwork::V4(network) => {
            IpCidr::Ipv4(Ipv4Cidr::new(network.ip().into(), network.prefix()))
        }
        IpNetwork::V6(network) => {
            IpCidr::Ipv6(Ipv6Cidr::new(network.ip().into(), network.prefix()))
        }
    }
}
