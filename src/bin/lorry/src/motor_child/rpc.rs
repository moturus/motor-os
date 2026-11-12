//! One authenticated child connection; stdio remains attached to the caller.

use moto_sdk::ipc::sync::{ClientConnection, LocalServerConnection, RequestHeader, ResponseHeader};
use moto_sdk::sys::{SysHandle, SysObj};
use serde::{Serialize, de::DeserializeOwned};

use crate::diagnostic::{Error, Result};

// The SDK owns the header, including its sequence counter. Never overwrite it.
const PAYLOAD: usize = 24;
const MAX_REQUEST: usize = 2 * 1024 * 1024;
const LAST: u32 = 1;

pub(super) fn authenticate(handle: SysHandle, pid: u64, caps: u64) -> Result<()> {
    if SysObj::get_pid(handle).map_err(failure)? != pid
        || SysObj::get_capabilities(handle).map_err(failure)? != caps
    {
        return Err(Error::failure(
            "Lorry worker IPC peer does not match its process",
        ));
    }
    Ok(())
}

pub(super) fn failure(error: impl std::fmt::Display) -> Error {
    Error::failure(format!("Lorry worker IPC: {error}"))
}

fn write(data: &mut [u8], value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(failure)?;
    write_bytes(data, &bytes)
}

fn write_bytes(data: &mut [u8], bytes: &[u8]) -> Result<()> {
    if bytes.len() > data.len() - PAYLOAD {
        return Err(Error::failure("Lorry worker frame exceeds its channel"));
    }
    data[16..24].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    data[PAYLOAD..PAYLOAD + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn read_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let length = u64::from_le_bytes(data[16..24].try_into().unwrap());
    if length > (data.len() - PAYLOAD) as u64 {
        return Err(Error::failure("invalid Lorry worker message length"));
    }
    // Parse owned bytes, never structures borrowed from a mutable IPC page.
    Ok(data[PAYLOAD..PAYLOAD + length as usize].to_vec())
}

pub(super) fn call<T: DeserializeOwned>(
    client: &mut ClientConnection,
    request: &impl Serialize,
) -> Result<T> {
    let bytes = serde_json::to_vec(request).map_err(failure)?;
    if bytes.len() > MAX_REQUEST {
        return Err(Error::failure("Lorry worker request exceeds 2 MiB"));
    }
    let size = client.data().len() - PAYLOAD;
    let mut chunks = bytes.chunks(size).peekable();
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        write_bytes(client.data_mut(), chunk)?;
        let header = client.req::<RequestHeader>();
        header.cmd = 1;
        header.ver = 1;
        header.flags = if last { LAST } else { 0 };
        client.do_rpc(None).map_err(failure)?;
        if client.resp::<ResponseHeader>().ver != 1 {
            return Err(Error::failure("unsupported Lorry worker reply"));
        }
        let response: Result<Option<T>> =
            serde_json::from_slice(&read_bytes(client.data())?).map_err(failure)?;
        match (last, response?) {
            (true, Some(value)) => return Ok(value),
            (false, None) => {}
            _ => return Err(Error::failure("invalid Lorry worker chunk acknowledgment")),
        }
    }
    Err(Error::failure("empty Lorry worker request"))
}

#[derive(Default)]
pub(super) struct Receiver {
    bytes: Vec<u8>,
}

impl Receiver {
    pub(super) fn request<T: DeserializeOwned>(
        &mut self,
        connection: &LocalServerConnection,
    ) -> Result<Option<T>> {
        let header = connection.req::<RequestHeader>();
        if header.cmd != 1 || header.ver != 1 || header.flags & !LAST != 0 {
            return Err(Error::failure("unsupported Lorry worker request"));
        }
        let last = header.flags == LAST;
        let bytes = read_bytes(connection.data())?;
        if bytes.is_empty() || bytes.len() > MAX_REQUEST - self.bytes.len() {
            return Err(Error::failure("invalid Lorry worker request size"));
        }
        self.bytes.extend_from_slice(&bytes);
        if last {
            let result = serde_json::from_slice(&self.bytes).map_err(failure);
            self.bytes.clear();
            result.map(Some)
        } else {
            Ok(None)
        }
    }
}

pub(super) fn respond<T: Serialize>(
    connection: &mut LocalServerConnection,
    result: &Result<T>,
) -> Result<()> {
    write(connection.data_mut(), result)?;
    let header = connection.resp::<ResponseHeader>();
    header.result = 0;
    header.ver = 1;
    connection.finish_rpc().map_err(failure)
}
