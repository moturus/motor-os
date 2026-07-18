//! Wire protocol and client for the Motor OS DNS resolver service.
//!
//! The service deliberately returns only address-family/address-byte pairs.
//! libc-owned pointers and POSIX `EAI_*` values never cross the IPC boundary.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use moto_ipc::sync::{ChannelSize, ClientConnection, RequestHeader, ResponseHeader};

pub const SERVICE_URL: &str = "moto-dns-resolver";
pub const PROTOCOL_VERSION: u16 = 1;
pub const CMD_LOOKUP: u16 = 1;

/// Maximum textual DNS name, excluding the terminating NUL.
pub const MAX_NAME_LEN: usize = 253;
pub const MAX_ADDRESSES: usize = 16;

/// mlibc uses a five-second DNS timeout per address family. Allow one second
/// for IPC overhead and, for `Any`, a second five-second family lookup.
const ONE_FAMILY_TIMEOUT: Duration = Duration::from_secs(6);
const ANY_FAMILY_TIMEOUT: Duration = Duration::from_secs(11);

pub const RESPONSE_FLAG_TRUNCATED: u16 = 1;
const RESPONSE_KNOWN_FLAGS: u16 = RESPONSE_FLAG_TRUNCATED;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    V4 = 1,
    V6 = 2,
    Any = 3,
}

impl TryFrom<u8> for AddressFamily {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V4),
            2 => Ok(Self::V6),
            3 => Ok(Self::Any),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    TemporaryFailure = 2,
    OutOfMemory = 3,
    UnsupportedFamily = 4,
    TimedOut = 5,
    System = 6,
    ResolverFailure = 7,
    InvalidRequest = 8,
    Busy = 9,
}

impl TryFrom<u8> for Status {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::NotFound),
            2 => Ok(Self::TemporaryFailure),
            3 => Ok(Self::OutOfMemory),
            4 => Ok(Self::UnsupportedFamily),
            5 => Ok(Self::TimedOut),
            6 => Ok(Self::System),
            7 => Ok(Self::ResolverFailure),
            8 => Ok(Self::InvalidRequest),
            9 => Ok(Self::Busy),
            _ => Err(()),
        }
    }
}

/// A stable, pointer-free address representation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub family: u8,
    pub reserved: [u8; 3],
    pub bytes: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<Address>() == 20);

impl Address {
    pub const fn zeroed() -> Self {
        Self {
            family: 0,
            reserved: [0; 3],
            bytes: [0; 16],
        }
    }

    pub fn address_family(&self) -> Result<AddressFamily, ProtocolError> {
        AddressFamily::try_from(self.family).map_err(|_| ProtocolError::AddressFamily)
    }
}

#[repr(C, align(8))]
pub struct LookupRequest {
    pub header: RequestHeader,
    pub request_id: u64,
    pub name_len: u16,
    pub family: u8,
    pub reserved_0: u8,
    pub reserved_1: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub reserved_tail: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<LookupRequest>() == 288);

#[repr(C, align(8))]
pub struct LookupResponse {
    pub header: ResponseHeader,
    pub request_id: u64,
    pub status: u8,
    pub address_count: u8,
    pub flags: u16,
    pub reserved: u32,
    pub addresses: [Address; MAX_ADDRESSES],
}

const _: () = assert!(core::mem::size_of::<LookupResponse>() == 352);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Command,
    Version,
    Flags,
    Family,
    NameLength,
    EmbeddedNul,
    Reserved,
}

pub fn validate_request(request: &LookupRequest) -> Result<(&[u8], AddressFamily), RequestError> {
    if request.header.cmd != CMD_LOOKUP {
        return Err(RequestError::Command);
    }
    if request.header.ver != PROTOCOL_VERSION {
        return Err(RequestError::Version);
    }
    if request.header.flags != 0 {
        return Err(RequestError::Flags);
    }
    if request.reserved_0 != 0 || request.reserved_1 != 0 || request.reserved_tail != [0; 3] {
        return Err(RequestError::Reserved);
    }

    let family = AddressFamily::try_from(request.family).map_err(|_| RequestError::Family)?;
    let name_len = request.name_len as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return Err(RequestError::NameLength);
    }
    let name = &request.name[..name_len];
    if name.contains(&0) {
        return Err(RequestError::EmbeddedNul);
    }
    Ok((name, family))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Header,
    Version,
    RequestId,
    Status,
    Flags,
    Count,
    AddressFamily,
    AddressContents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    InvalidName,
    ServiceUnavailable,
    TimedOut,
    Transport(moto_rt::ErrorCode),
    Protocol(ProtocolError),
    Resolver(Status),
}

#[derive(Debug)]
pub struct LookupResult {
    pub addresses: Vec<Address>,
    pub truncated: bool,
}

pub struct Client {
    connection: ClientConnection,
    next_request_id: u64,
}

impl Client {
    /// Connect to the resolver. A missing or not-yet-started service is always
    /// reported as `ServiceUnavailable`; callers may retry by constructing a
    /// new client later.
    pub fn connect() -> Result<Self, ClientError> {
        Self::connect_to(SERVICE_URL)
    }

    /// Connect to an explicitly named endpoint. This is primarily useful to
    /// verify service-discovery failure without stopping the system resolver.
    pub fn connect_to(service_url: &str) -> Result<Self, ClientError> {
        let mut connection =
            ClientConnection::new(ChannelSize::Small).map_err(ClientError::Transport)?;
        connection
            .connect(service_url)
            .map_err(|_| ClientError::ServiceUnavailable)?;
        Ok(Self {
            connection,
            next_request_id: 1,
        })
    }

    pub fn lookup(
        &mut self,
        name: &str,
        family: AddressFamily,
    ) -> Result<LookupResult, ClientError> {
        let name = name.as_bytes();
        if name.is_empty() || name.len() > MAX_NAME_LEN || name.contains(&0) {
            return Err(ClientError::InvalidName);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);

        {
            let request = self.connection.req::<LookupRequest>();
            request.header.cmd = CMD_LOOKUP;
            request.header.ver = PROTOCOL_VERSION;
            request.header.flags = 0;
            request.request_id = request_id;
            request.name_len = name.len() as u16;
            request.family = family as u8;
            request.reserved_0 = 0;
            request.reserved_1 = 0;
            request.name.fill(0);
            request.name[..name.len()].copy_from_slice(name);
            request.reserved_tail.fill(0);
        }

        let timeout = match family {
            AddressFamily::Any => ANY_FAMILY_TIMEOUT,
            AddressFamily::V4 | AddressFamily::V6 => ONE_FAMILY_TIMEOUT,
        };
        let deadline = moto_rt::time::Instant::now()
            .checked_add_duration(&timeout)
            .unwrap_or_else(moto_rt::time::Instant::infinite_future);
        self.connection
            .do_rpc(Some(deadline))
            .map_err(|error| match error {
                moto_rt::E_TIMED_OUT => ClientError::TimedOut,
                moto_rt::E_BAD_HANDLE | moto_rt::E_NOT_FOUND => ClientError::ServiceUnavailable,
                other => ClientError::Transport(other),
            })?;

        let response = self.connection.resp::<LookupResponse>();
        if response.header.result != moto_rt::E_OK {
            return Err(ClientError::Protocol(ProtocolError::Header));
        }
        if response.header.ver != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(ProtocolError::Version));
        }
        if response.request_id != request_id {
            return Err(ClientError::Protocol(ProtocolError::RequestId));
        }
        let status = Status::try_from(response.status)
            .map_err(|_| ClientError::Protocol(ProtocolError::Status))?;
        if response.flags & !RESPONSE_KNOWN_FLAGS != 0 || response.reserved != 0 {
            return Err(ClientError::Protocol(ProtocolError::Flags));
        }
        let count = response.address_count as usize;
        if count > MAX_ADDRESSES {
            return Err(ClientError::Protocol(ProtocolError::Count));
        }
        if status != Status::Ok {
            if count != 0 {
                return Err(ClientError::Protocol(ProtocolError::Count));
            }
            return Err(ClientError::Resolver(status));
        }
        if count == 0 {
            return Err(ClientError::Protocol(ProtocolError::Count));
        }

        let mut addresses = Vec::with_capacity(count);
        for address in response.addresses[..count].iter().copied() {
            let address_family = address.address_family().map_err(ClientError::Protocol)?;
            if address_family == AddressFamily::Any
                || address.reserved != [0; 3]
                || (address_family == AddressFamily::V4 && address.bytes[4..] != [0; 12])
                || (family != AddressFamily::Any && family != address_family)
            {
                return Err(ClientError::Protocol(ProtocolError::AddressContents));
            }
            addresses.push(address);
        }

        Ok(LookupResult {
            addresses,
            truncated: response.flags & RESPONSE_FLAG_TRUNCATED != 0,
        })
    }
}
