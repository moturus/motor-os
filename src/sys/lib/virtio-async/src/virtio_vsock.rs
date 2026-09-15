//! Virtio 1.1 socket wire handling; connection policy belongs to sys-io.
use core::mem::{offset_of, size_of};
use std::cell::RefCell;
use std::io::{ErrorKind, Result as IoResult};
use std::rc::Rc;

use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use moto_tooling::iobuf::IoBuf;

use crate::WriteCompletion;
use crate::virtio_device::{VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1, VirtioDevice};
use crate::virtio_queue::{UserData, Virtqueue};

pub const HEADER_LEN: usize = 44;
pub const EVENT_LEN: usize = 4;
pub const SHUTDOWN_RECEIVE: u32 = 1;
pub const SHUTDOWN_SEND: u32 = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct WireHeader {
    src_cid: [u8; 8],
    dst_cid: [u8; 8],
    src_port: [u8; 4],
    dst_port: [u8; 4],
    len: [u8; 4],
    socket_type: [u8; 2],
    operation: [u8; 2],
    flags: [u8; 4],
    buf_alloc: [u8; 4],
    fwd_cnt: [u8; 4],
}

#[repr(C)]
struct WireEvent {
    id: [u8; 4],
}

const _: () = {
    assert!(size_of::<WireHeader>() == HEADER_LEN);
    assert!(size_of::<WireEvent>() == EVENT_LEN);
    assert!(offset_of!(WireHeader, src_cid) == 0);
    assert!(offset_of!(WireHeader, dst_cid) == 8);
    assert!(offset_of!(WireHeader, src_port) == 16);
    assert!(offset_of!(WireHeader, dst_port) == 20);
    assert!(offset_of!(WireHeader, len) == 24);
    assert!(offset_of!(WireHeader, socket_type) == 28);
    assert!(offset_of!(WireHeader, operation) == 30);
    assert!(offset_of!(WireHeader, flags) == 32);
    assert!(offset_of!(WireHeader, buf_alloc) == 36);
    assert!(offset_of!(WireHeader, fwd_cnt) == 40);
};

/// Virtio 1.1 defines no socket-specific features; reuse only split-ring events.
pub fn select_features(offered: u64) -> IoResult<u64> {
    if offered & VIRTIO_F_VERSION_1 == 0 {
        return Err(ErrorKind::Unsupported.into());
    }

    Ok(VIRTIO_F_VERSION_1 | (offered & VIRTIO_F_RING_EVENT_IDX))
}

pub(crate) fn negotiate_features(device: &mut VirtioDevice) -> IoResult<()> {
    let selected = select_features(device.get_available_features())?;
    device.write_enabled_features(selected);
    device.confirm_features()?;
    device.virtio_features_negotiated = selected;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketType {
    Stream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Request,
    Response,
    Reset,
    Shutdown,
    ReadWrite,
    CreditUpdate,
    CreditRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHeader {
    pub src_cid: u32,
    pub dst_cid: u32,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub socket_type: SocketType,
    pub operation: Operation,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub socket_type: u16,
    pub operation: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeErrorKind {
    ShortHeader,
    LengthOverflow,
    UsedLengthExceedsCapacity,
    PayloadExceedsCapacity,
    TruncatedPayload,
    TrailingPayload,
    CidTooWide,
    UnknownSocketType,
    UnknownOperation,
    InvalidFlags,
    ControlPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub kind: DecodeErrorKind,
    /// Unvalidated metadata for protocol refusal, present only for a complete
    /// received header. It is not authority to access a connection or payload.
    pub raw: Option<RawHeader>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    TransportReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    InvalidLength,
    Unknown(u32),
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn raw_header(bytes: &[u8]) -> RawHeader {
    RawHeader {
        src_cid: read_u64(bytes, 0),
        dst_cid: read_u64(bytes, 8),
        src_port: read_u32(bytes, 16),
        dst_port: read_u32(bytes, 20),
        len: read_u32(bytes, 24),
        socket_type: read_u16(bytes, 28),
        operation: read_u16(bytes, 30),
        flags: read_u32(bytes, 32),
        buf_alloc: read_u32(bytes, 36),
        fwd_cnt: read_u32(bytes, 40),
    }
}

fn encode_header(raw: RawHeader) -> WireHeader {
    WireHeader {
        src_cid: raw.src_cid.to_le_bytes(),
        dst_cid: raw.dst_cid.to_le_bytes(),
        src_port: raw.src_port.to_le_bytes(),
        dst_port: raw.dst_port.to_le_bytes(),
        len: raw.len.to_le_bytes(),
        socket_type: raw.socket_type.to_le_bytes(),
        operation: raw.operation.to_le_bytes(),
        flags: raw.flags.to_le_bytes(),
        buf_alloc: raw.buf_alloc.to_le_bytes(),
        fwd_cnt: raw.fwd_cnt.to_le_bytes(),
    }
}

pub(crate) fn validate_payload_dma(capacity: usize, len: usize, phys_addr: u64) -> IoResult<u32> {
    let len = u32::try_from(len).map_err(|_| ErrorKind::InvalidInput)?;
    if capacity != PAGE_SIZE_SMALL as usize
        || len == 0
        || len as usize > capacity
        || !phys_addr.is_multiple_of(PAGE_SIZE_SMALL)
    {
        return Err(ErrorKind::InvalidInput.into());
    }
    Ok(len)
}

fn validate_tx_header(raw: RawHeader, payload_len: u32) -> IoResult<()> {
    if raw.src_cid > u32::MAX as u64
        || raw.dst_cid > u32::MAX as u64
        || raw.len != payload_len
        || (raw.socket_type != 1 && raw.operation != 3)
    {
        return Err(ErrorKind::InvalidInput.into());
    }
    let valid_flags = match raw.operation {
        4 => raw.flags & !(SHUTDOWN_RECEIVE | SHUTDOWN_SEND) == 0,
        1 | 2 | 3 | 5 | 6 | 7 => raw.flags == 0,
        _ => false,
    };
    if !valid_flags || (raw.operation != 5 && payload_len != 0) {
        return Err(ErrorKind::InvalidInput.into());
    }
    Ok(())
}

/// Try to publish one TX packet without waiting. Rejection leaves the queue
/// unpublished and returns the caller's payload unchanged.
pub(crate) fn try_post_tx(
    queue: Rc<RefCell<Virtqueue>>,
    raw: RawHeader,
    payload: Option<IoBuf>,
) -> std::result::Result<WriteCompletion<Option<IoBuf>>, (std::io::Error, Option<IoBuf>)> {
    let payload_data = match payload.as_ref() {
        Some(bytes) => {
            validate_payload_dma(bytes.capacity(), bytes.len(), bytes.phys_addr() as u64).map(
                |len| UserData {
                    phys_addr: bytes.phys_addr() as u64,
                    len,
                },
            )
        }
        None => Ok(UserData {
            phys_addr: 0,
            len: 0,
        }),
    };
    let payload_data = match payload_data {
        Ok(data) => data,
        Err(err) => return Err((err, payload)),
    };
    if let Err(err) = validate_tx_header(raw, payload_data.len) {
        return Err((err, payload));
    }

    let descriptor_count = if payload.is_some() { 2 } else { 1 };
    let (chain_head, header_data) = {
        let mut queue = queue.borrow_mut();
        let Some(chain_head) = queue.alloc_descriptor_chain(descriptor_count) else {
            return Err((ErrorKind::WouldBlock.into(), payload));
        };
        let (header, phys_addr, _) = queue.get_buffer::<WireHeader>(chain_head);
        *header = encode_header(raw);
        (
            chain_head,
            UserData {
                phys_addr,
                len: HEADER_LEN as u32,
            },
        )
    };
    let data = [header_data, payload_data];
    let descriptors = &data[..descriptor_count as usize];
    Ok(WriteCompletion {
        vq_completion: Virtqueue::add_buffs(
            queue,
            descriptors,
            descriptor_count,
            0,
            chain_head,
            payload,
        ),
    })
}

/// Decode a copied header after completion. `bytes` need not contain the
/// separately posted payload; `used_len` covers both descriptors. The caller
/// may expose the returned payload length only within that posted buffer.
pub fn decode_packet(
    bytes: &[u8],
    used_len: u32,
    posted_payload_capacity: usize,
) -> Result<PacketHeader, DecodeError> {
    if bytes.len() < HEADER_LEN || used_len < HEADER_LEN as u32 {
        return Err(DecodeError {
            kind: DecodeErrorKind::ShortHeader,
            raw: None,
        });
    }

    let raw = raw_header(bytes);
    let fail = |kind| DecodeError {
        kind,
        raw: Some(raw),
    };
    let expected_len = (HEADER_LEN as u32)
        .checked_add(raw.len)
        .ok_or_else(|| fail(DecodeErrorKind::LengthOverflow))?;
    if used_len as usize > HEADER_LEN.saturating_add(posted_payload_capacity) {
        return Err(fail(DecodeErrorKind::UsedLengthExceedsCapacity));
    }
    if raw.len as usize > posted_payload_capacity {
        return Err(fail(DecodeErrorKind::PayloadExceedsCapacity));
    }
    if used_len < expected_len {
        return Err(fail(DecodeErrorKind::TruncatedPayload));
    }
    if used_len > expected_len {
        return Err(fail(DecodeErrorKind::TrailingPayload));
    }
    if raw.src_cid > u32::MAX as u64 || raw.dst_cid > u32::MAX as u64 {
        return Err(fail(DecodeErrorKind::CidTooWide));
    }
    let socket_type = match raw.socket_type {
        1 => SocketType::Stream,
        _ => return Err(fail(DecodeErrorKind::UnknownSocketType)),
    };
    let operation = match raw.operation {
        1 => Operation::Request,
        2 => Operation::Response,
        3 => Operation::Reset,
        4 => Operation::Shutdown,
        5 => Operation::ReadWrite,
        6 => Operation::CreditUpdate,
        7 => Operation::CreditRequest,
        _ => return Err(fail(DecodeErrorKind::UnknownOperation)),
    };
    let valid_flags = match operation {
        Operation::Shutdown => raw.flags & !(SHUTDOWN_RECEIVE | SHUTDOWN_SEND) == 0,
        _ => raw.flags == 0,
    };
    if !valid_flags {
        return Err(fail(DecodeErrorKind::InvalidFlags));
    }
    if operation != Operation::ReadWrite && raw.len != 0 {
        return Err(fail(DecodeErrorKind::ControlPayload));
    }

    Ok(PacketHeader {
        src_cid: raw.src_cid as u32,
        dst_cid: raw.dst_cid as u32,
        src_port: raw.src_port,
        dst_port: raw.dst_port,
        len: raw.len,
        socket_type,
        operation,
        flags: raw.flags,
        buf_alloc: raw.buf_alloc,
        fwd_cnt: raw.fwd_cnt,
    })
}

pub fn decode_event(bytes: &[u8], used_len: u32) -> Result<Event, EventError> {
    if used_len != EVENT_LEN as u32 || bytes.len() < EVENT_LEN {
        return Err(EventError::InvalidLength);
    }
    match read_u32(bytes, 0) {
        0 => Ok(Event::TransportReset),
        event => Err(EventError::Unknown(event)),
    }
}
