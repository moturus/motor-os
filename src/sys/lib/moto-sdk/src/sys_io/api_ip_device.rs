//! Registration data for a process-backed IP interface, encoded in one page.
use alloc::{string::String, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use moto_rt::{Error, Result};

pub const MAX_NAME: usize = 31;
pub const MAX_ADDRESSES: usize = 16;
pub const MAX_ROUTES: usize = 128;
pub const MAX_MTU: u16 = crate::ipc::io_channel::PAGE_SIZE as u16;
const HEADER: usize = 8;
const CIDR_SIZE: usize = 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    pub fn network(self) -> Result<Self> {
        let bits = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix_len > bits {
            return Err(Error::InvalidArgument);
        }
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u128::MAX << (bits - self.prefix_len)
        };
        let address = match self.address {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask as u32)),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask)),
        };
        Ok(Self { address, ..self })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    pub name: String,
    pub addresses: Vec<Cidr>,
    pub routes: Vec<Cidr>,
    pub mtu: u16,
}

impl Registration {
    pub fn validate(&self) -> Result<()> {
        let invalid = Error::InvalidArgument;
        if self.name.is_empty()
            || self.name.len() > MAX_NAME
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || self.addresses.is_empty()
            || self.addresses.len() > MAX_ADDRESSES
            || self.routes.len() > MAX_ROUTES
            || self.mtu > MAX_MTU
            || self.mtu < 576
        {
            return Err(invalid);
        }
        for (i, cidr) in self.addresses.iter().enumerate() {
            cidr.network()?;
            if cidr.address.is_unspecified()
                || cidr.address.is_multicast()
                || matches!(cidr.address, IpAddr::V4(ip) if ip.is_broadcast())
                || (cidr.address.is_ipv6() && self.mtu < 1280)
                || self.addresses[..i]
                    .iter()
                    .any(|old| old.address == cidr.address)
            {
                return Err(invalid);
            }
        }
        for (i, cidr) in self.routes.iter().enumerate() {
            if cidr.network()? != *cidr
                || self.routes[..i].contains(cidr)
                || !self
                    .addresses
                    .iter()
                    .any(|addr| addr.address.is_ipv4() == cidr.address.is_ipv4())
            {
                return Err(invalid);
            }
        }
        Ok(())
    }

    pub fn encode(&self, bytes: &mut [u8]) -> Result<usize> {
        self.validate()?;
        let length =
            HEADER + self.name.len() + (self.addresses.len() + self.routes.len()) * CIDR_SIZE;
        let bytes = bytes.get_mut(..length).ok_or(Error::InvalidArgument)?;
        bytes.fill(0);
        bytes[..4].copy_from_slice(&[
            1,
            self.name.len() as u8,
            self.addresses.len() as u8,
            self.routes.len() as u8,
        ]);
        bytes[4..6].copy_from_slice(&self.mtu.to_le_bytes());
        bytes[HEADER..HEADER + self.name.len()].copy_from_slice(self.name.as_bytes());
        for (encoded, cidr) in bytes[HEADER + self.name.len()..]
            .as_chunks_mut::<CIDR_SIZE>()
            .0
            .iter_mut()
            .zip(self.addresses.iter().chain(&self.routes))
        {
            encoded[1] = cidr.prefix_len;
            match cidr.address {
                IpAddr::V4(ip) => {
                    encoded[0] = 4;
                    encoded[2..6].copy_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    encoded[0] = 6;
                    encoded[2..].copy_from_slice(&ip.octets());
                }
            }
        }
        Ok(length)
    }

    /// Decode only a private copy: a provider may mutate shared page bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let invalid = Error::InvalidArgument;
        if bytes.len() < HEADER || bytes[0] != 1 || bytes[6..8] != [0, 0] {
            return Err(invalid);
        }
        let (name_len, addresses, routes) =
            (bytes[1] as usize, bytes[2] as usize, bytes[3] as usize);
        if name_len == 0
            || name_len > MAX_NAME
            || addresses == 0
            || addresses > MAX_ADDRESSES
            || routes > MAX_ROUTES
            || bytes.len() != HEADER + name_len + (addresses + routes) * CIDR_SIZE
        {
            return Err(invalid);
        }
        let mut config = Self {
            name: String::new(),
            addresses: Vec::new(),
            routes: Vec::new(),
            mtu: u16::from_le_bytes([bytes[4], bytes[5]]),
        };
        config
            .name
            .try_reserve_exact(name_len)
            .map_err(|_| Error::OutOfMemory)?;
        config.name.push_str(
            core::str::from_utf8(&bytes[HEADER..HEADER + name_len]).map_err(|_| invalid)?,
        );
        config
            .addresses
            .try_reserve_exact(addresses)
            .map_err(|_| Error::OutOfMemory)?;
        config
            .routes
            .try_reserve_exact(routes)
            .map_err(|_| Error::OutOfMemory)?;
        for (i, encoded) in bytes[HEADER + name_len..]
            .as_chunks::<CIDR_SIZE>()
            .0
            .iter()
            .enumerate()
        {
            let address = match encoded[0] {
                4 if encoded[6..].iter().all(|byte| *byte == 0) => {
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&encoded[2..6]).unwrap()))
                }
                6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&encoded[2..]).unwrap())),
                _ => return Err(invalid),
            };
            let cidr = Cidr {
                address,
                prefix_len: encoded[1],
            };
            if i < addresses {
                config.addresses.push(cidr);
            } else {
                config.routes.push(cidr);
            }
        }
        config.validate()?;
        Ok(config)
    }
}
