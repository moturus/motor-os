use base64::{Engine, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use moto_netstack::wire::IpCidr;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub type Result<T> = std::result::Result<T, &'static str>;

pub struct Options {
    pub bind: SocketAddr,
    pub addresses: Vec<IpCidr>,
    pub endpoint: Option<SocketAddr>,
    pub keys: Option<Keys>,
}

pub struct Keys {
    pub private: [u8; 32],
    pub peer: [u8; 32],
    pub psk: Option<[u8; 32]>,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut bind = None;
        let mut addresses = Vec::new();
        let mut endpoint = None;
        let mut private = None;
        let mut peer = None;
        let mut psk = None;
        let mut plain = false;
        let mut args = args.iter();
        while let Some(option) = args.next() {
            if option == "--plain" && !plain {
                plain = true;
                continue;
            }
            let value = args.next().ok_or("missing option value")?;
            match option.as_str() {
                "--bind" if bind.is_none() => {
                    bind = Some(value.parse().map_err(|_| "invalid bind address")?);
                }
                "--address" if addresses.len() < 16 => {
                    let address: IpCidr = value.parse().map_err(|_| "invalid inner address")?;
                    let ip: std::net::IpAddr = address.address().into();
                    if ip.is_unspecified() || ip.is_multicast() || addresses.contains(&address) {
                        return Err("inner address must be unique and unicast");
                    }
                    addresses.push(address);
                }
                "--endpoint" if endpoint.is_none() => {
                    endpoint = Some(value.parse().map_err(|_| "invalid endpoint")?);
                }
                "--private-key" if private.is_none() => private = Some(read_key(value, true)?),
                "--peer-key" if peer.is_none() => peer = Some(read_key(value, false)?),
                "--psk" if psk.is_none() => psk = Some(read_key(value, true)?),
                _ => return Err("unknown or duplicate option"),
            }
        }
        let endpoint: Option<SocketAddr> = endpoint;
        if let Some(endpoint) = endpoint
            && (endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast())
        {
            return Err("endpoint must be unicast with a nonzero port");
        }
        if addresses.is_empty() {
            return Err("at least one inner address is required");
        }
        let keys = if plain {
            if private.is_some() || peer.is_some() || psk.is_some() || endpoint.is_none() {
                return Err("plain mode requires an endpoint and no keys");
            }
            None
        } else {
            Some(Keys {
                private: private.ok_or("missing private key")?,
                peer: peer.ok_or("missing peer public key")?,
                psk,
            })
        };
        Ok(Self {
            bind: bind.ok_or("missing bind address")?,
            addresses,
            endpoint,
            keys,
        })
    }
}

fn read_key(path: &str, secret: bool) -> Result<[u8; 32]> {
    let file = std::fs::File::open(path).map_err(|_| "cannot open key file")?;
    let metadata = file.metadata().map_err(|_| "cannot inspect key file")?;
    if !metadata.is_file() || (secret && metadata.permissions().mode() & 0o077 != 0) {
        return Err("secret key must be a private regular file");
    }
    let mut bytes = Vec::new();
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read key file")?;
    if bytes.len() > 128 {
        return Err("key file too large");
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "invalid key encoding")?;
    STANDARD
        .decode(text.trim())
        .map_err(|_| "invalid key encoding")?
        .try_into()
        .map_err(|_| "key must contain 32 bytes")
}

pub fn keygen(private_path: &str, public_path: &str) -> Result<()> {
    let mut private = [0; 32];
    getrandom::getrandom(&mut private).map_err(|_| "cannot generate key")?;
    let public = PublicKey::from(&StaticSecret::from(private));
    for (path, key) in [(private_path, &private), (public_path, public.as_bytes())] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "cannot create key file")?;
        writeln!(file, "{}", STANDARD.encode(key)).map_err(|_| "cannot write key file")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_files_are_private_and_existing_files_are_preserved() {
        let directory = std::env::temp_dir().join(format!("wg-peer-keys-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let private = directory.join("private");
        let public = directory.join("public");
        let (private, public) = (private.to_str().unwrap(), public.to_str().unwrap());
        keygen(private, public).unwrap();
        let secret = read_key(private, true).unwrap();
        assert_eq!(
            read_key(public, false).unwrap(),
            *PublicKey::from(&StaticSecret::from(secret)).as_bytes()
        );
        assert!(keygen(private, public).is_err());
        assert_eq!(read_key(private, true).unwrap(), secret);
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(private, true).is_err());
        std::fs::write(public, "not a key").unwrap();
        assert!(read_key(public, false).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
