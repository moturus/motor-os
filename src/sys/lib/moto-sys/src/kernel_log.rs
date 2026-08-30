//! Framing shared by the kernel log producer and sys-tty consumer.

use core::sync::atomic::{fence, AtomicU64, Ordering};

pub const KERNEL_LOG_RING_SIZE: usize = 64 * 1024;
pub const KERNEL_LOG_FRAME_HEADER_SIZE: usize = 8;
pub const KERNEL_LOG_MAX_PAYLOAD: usize = KERNEL_LOG_RING_SIZE - KERNEL_LOG_FRAME_HEADER_SIZE;
pub const KERNEL_LOG_FRAME_MAGIC_V1: u16 = u16::from_le_bytes(*b"K1");

const RING_MASK: usize = KERNEL_LOG_RING_SIZE - 1;

const _: () = assert!(KERNEL_LOG_RING_SIZE.is_power_of_two());
const _: () = assert!(KERNEL_LOG_MAX_PAYLOAD <= u16::MAX as usize);

#[repr(C, align(8))]
pub struct KernelLogControl {
    pub generation: AtomicU64,
    pub end: AtomicU64,
}

impl KernelLogControl {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            end: AtomicU64::new(0),
        }
    }
}

impl Default for KernelLogControl {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<KernelLogControl>() == 16);
const _: () = assert!(core::mem::align_of::<KernelLogControl>() == 8);

pub const fn kernel_log_control_is_aligned(addr: usize) -> bool {
    addr & (core::mem::align_of::<KernelLogControl>() - 1) == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelLogFrameError {
    BufferTooSmall,
    PayloadTooLarge,
    BadMagic,
    TruncatedHeader,
    TruncatedPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedKernelLogFrame<'a> {
    pub sequence: u32,
    pub payload: &'a [u8],
    pub encoded_len: usize,
}

pub fn encode_kernel_log_frame(
    dst: &mut [u8],
    sequence: u32,
    payload: &[u8],
) -> Result<usize, KernelLogFrameError> {
    if payload.len() > KERNEL_LOG_MAX_PAYLOAD {
        return Err(KernelLogFrameError::PayloadTooLarge);
    }
    let encoded_len = KERNEL_LOG_FRAME_HEADER_SIZE + payload.len();
    if dst.len() < encoded_len {
        return Err(KernelLogFrameError::BufferTooSmall);
    }

    dst[..2].copy_from_slice(&KERNEL_LOG_FRAME_MAGIC_V1.to_le_bytes());
    dst[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    dst[4..8].copy_from_slice(&sequence.to_le_bytes());
    dst[8..encoded_len].copy_from_slice(payload);
    Ok(encoded_len)
}

pub fn decode_kernel_log_frame(
    src: &[u8],
) -> Result<DecodedKernelLogFrame<'_>, KernelLogFrameError> {
    if src.len() < KERNEL_LOG_FRAME_HEADER_SIZE {
        return Err(KernelLogFrameError::TruncatedHeader);
    }
    let magic = u16::from_le_bytes(src[..2].try_into().unwrap());
    if magic != KERNEL_LOG_FRAME_MAGIC_V1 {
        return Err(KernelLogFrameError::BadMagic);
    }

    let payload_len = u16::from_le_bytes(src[2..4].try_into().unwrap()) as usize;
    if payload_len > KERNEL_LOG_MAX_PAYLOAD {
        return Err(KernelLogFrameError::PayloadTooLarge);
    }
    let encoded_len = KERNEL_LOG_FRAME_HEADER_SIZE + payload_len;
    if src.len() < encoded_len {
        return Err(KernelLogFrameError::TruncatedPayload);
    }

    Ok(DecodedKernelLogFrame {
        sequence: u32::from_le_bytes(src[4..8].try_into().unwrap()),
        payload: &src[8..encoded_len],
        encoded_len,
    })
}

pub const fn kernel_log_sequence_gap(expected: u32, actual: u32) -> u32 {
    actual.wrapping_sub(expected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelLogSnapshot {
    Busy,
    Stable { end: u64, len: usize, lapped: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelLogSnapshotError {
    StagingTooSmall,
}

/// Copies one stable view of the ring.
///
/// `copy_from_ring` receives a physical ring offset and a destination slice.
/// It is called at most twice and must fill the complete destination.
pub fn snapshot_kernel_log_ring<F>(
    control: &KernelLogControl,
    previous_end: u64,
    staging: &mut [u8],
    mut copy_from_ring: F,
) -> Result<KernelLogSnapshot, KernelLogSnapshotError>
where
    F: FnMut(usize, &mut [u8]),
{
    let first_generation = control.generation.load(Ordering::Acquire);
    if first_generation & 1 != 0 {
        return Ok(KernelLogSnapshot::Busy);
    }

    let end = control.end.load(Ordering::Relaxed);
    let distance = end.wrapping_sub(previous_end);
    let lapped = distance > KERNEL_LOG_RING_SIZE as u64;
    let len = if lapped { 0 } else { distance as usize };
    if staging.len() < len {
        return Err(KernelLogSnapshotError::StagingTooSmall);
    }

    if len != 0 {
        let start = previous_end as usize & RING_MASK;
        let first_len = len.min(KERNEL_LOG_RING_SIZE - start);
        copy_from_ring(start, &mut staging[..first_len]);
        if first_len != len {
            copy_from_ring(0, &mut staging[first_len..len]);
        }
    }

    fence(Ordering::Acquire);
    let second_generation = control.generation.load(Ordering::Relaxed);
    if first_generation != second_generation || second_generation & 1 != 0 {
        return Ok(KernelLogSnapshot::Busy);
    }

    Ok(KernelLogSnapshot::Stable { end, len, lapped })
}
