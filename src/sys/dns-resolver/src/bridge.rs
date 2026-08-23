use std::net::IpAddr;

use moto_dns::{Address, AddressFamily, Status, MAX_ADDRESSES};

const HOSTS_PATH: &str = "/system/cfg/libc/hosts";
const RESOLV_CONF_PATH: &str = "/system/cfg/libc/resolv.conf";
const MAX_NAMESERVERS: usize = 2;

pub struct Result {
    pub status: Status,
    pub addresses: [Address; MAX_ADDRESSES],
    pub len: usize,
    pub truncated: bool,
}

pub fn lookup(name: &[u8], family: AddressFamily) -> Result {
    let Some(name) = canonical_name(name) else {
        return failure(Status::InvalidRequest);
    };
    if let Ok(address) = std::str::from_utf8(&name).unwrap().parse::<IpAddr>() {
        return if family_matches(address, family) {
            success([address])
        } else {
            failure(Status::NotFound)
        };
    }

    if let Ok(contents) = std::fs::read_to_string(HOSTS_PATH) {
        let addresses = hosts_lookup(&contents, &name, family);
        if !addresses.is_empty() {
            return success(addresses);
        }
    }

    let servers = match std::fs::read_to_string(RESOLV_CONF_PATH) {
        Ok(contents) => nameservers(&contents),
        Err(_) => return failure(Status::TemporaryFailure),
    };
    if servers.is_empty() {
        return failure(Status::TemporaryFailure);
    }

    let v4 = (family != AddressFamily::V6).then(|| super::dns::lookup(&name, 1, &servers));
    let v6 = (family != AddressFamily::V4).then(|| super::dns::lookup(&name, 28, &servers));
    let mut addresses = Vec::new();
    if let Some(Ok(found)) = &v4 {
        addresses.extend(found);
    }
    if let Some(Ok(found)) = &v6 {
        addresses.extend(found);
    }
    if !addresses.is_empty() {
        return success(addresses);
    }

    failure(merge_failures(v4.as_ref(), v6.as_ref()))
}

fn canonical_name(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 253 || name.contains(&0) || !name.is_ascii() {
        return None;
    }
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty()
        || name
            .split(|byte| *byte == b'.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return None;
    }
    Some(name.iter().map(u8::to_ascii_lowercase).collect())
}

fn hosts_lookup(contents: &str, name: &[u8], family: AddressFamily) -> Vec<IpAddr> {
    let Ok(name) = std::str::from_utf8(name) else {
        return Vec::new();
    };
    let mut addresses = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        let Some(address) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
            continue;
        };
        if family_matches(address, family)
            && fields.any(|alias| alias.trim_end_matches('.').eq_ignore_ascii_case(name))
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    addresses
}

fn nameservers(contents: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(server) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
            continue;
        };
        if !server.is_unspecified() && !servers.contains(&server) {
            servers.push(server);
            if servers.len() == MAX_NAMESERVERS {
                break;
            }
        }
    }
    servers
}

fn family_matches(address: IpAddr, family: AddressFamily) -> bool {
    family == AddressFamily::Any
        || matches!(
            (address, family),
            (IpAddr::V4(_), AddressFamily::V4) | (IpAddr::V6(_), AddressFamily::V6)
        )
}

fn success(addresses: impl IntoIterator<Item = IpAddr>) -> Result {
    let mut result = Result {
        status: Status::Ok,
        addresses: [Address::zeroed(); MAX_ADDRESSES],
        len: 0,
        truncated: false,
    };
    for address in addresses {
        if result.len == MAX_ADDRESSES {
            result.truncated = true;
            break;
        }
        result.addresses[result.len] = match address {
            IpAddr::V4(address) => Address {
                family: AddressFamily::V4 as u8,
                reserved: [0; 3],
                bytes: {
                    let mut bytes = [0; 16];
                    bytes[..4].copy_from_slice(&address.octets());
                    bytes
                },
            },
            IpAddr::V6(address) => Address {
                family: AddressFamily::V6 as u8,
                reserved: [0; 3],
                bytes: address.octets(),
            },
        };
        result.len += 1;
    }
    result
}

fn failure(status: Status) -> Result {
    Result {
        status,
        addresses: [Address::zeroed(); MAX_ADDRESSES],
        len: 0,
        truncated: false,
    }
}

fn merge_failures(
    v4: Option<&std::result::Result<Vec<IpAddr>, Status>>,
    v6: Option<&std::result::Result<Vec<IpAddr>, Status>>,
) -> Status {
    let statuses = [v4, v6].map(|result| result.and_then(|result| result.as_ref().err().copied()));
    for preferred in [
        Status::TemporaryFailure,
        Status::TimedOut,
        Status::OutOfMemory,
        Status::System,
        Status::ResolverFailure,
    ] {
        if statuses.contains(&Some(preferred)) {
            return preferred;
        }
    }
    if statuses
        .iter()
        .flatten()
        .all(|status| *status == Status::NotFound)
    {
        Status::NotFound
    } else {
        Status::UnsupportedFamily
    }
}

pub fn self_test() {
    assert_eq!(canonical_name(b"Example.TEST.").unwrap(), b"example.test");
    assert!(canonical_name(b"bad..name").is_none());
    assert_eq!(
        hosts_lookup(
            "192.0.2.1 example.test alias\n2001:db8::1 alias # comment\n",
            b"alias",
            AddressFamily::Any,
        ),
        [
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        ]
    );
    assert_eq!(
        nameservers("nameserver 192.0.2.53\ninvalid\nnameserver 2001:db8::53\n"),
        [
            "192.0.2.53".parse::<IpAddr>().unwrap(),
            "2001:db8::53".parse::<IpAddr>().unwrap()
        ]
    );
    super::dns::self_test();
}
