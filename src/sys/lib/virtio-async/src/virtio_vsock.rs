//! Virtio 1.1 socket wire handling; connection policy belongs to sys-io.
use core::mem::{offset_of, size_of};
use std::cell::RefCell;
use std::io::{ErrorKind, Result as IoResult};
use std::rc::Rc;

use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use moto_tooling::iobuf::IoBuf;

use crate::WriteCompletion;
use crate::virtio_device::{VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1, VirtioDevice};
use crate::virtio_queue::{OrderedCompletions, UserData, Virtqueue, VqCompletion};

pub const HEADER_LEN: usize = 44;
pub const EVENT_LEN: usize = 4;
pub const SHUTDOWN_RECEIVE: u32 = 1;
pub const SHUTDOWN_SEND: u32 = 2;

pub fn validate_guest_cid(raw: u64) -> IoResult<u32> {
    let cid = u32::try_from(raw).map_err(|_| ErrorKind::InvalidData)?;
    if !(3..u32::MAX).contains(&cid) {
        return Err(ErrorKind::InvalidData.into());
    }
    Ok(cid)
}

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

pub(crate) fn read_guest_cid(device: &VirtioDevice) -> IoResult<u32> {
    let (bar, config_offset) = device.device_config(8)?;
    // Virtio 1.1 reserves the upper word as zero, so the existing low/high
    // 32-bit read needs no configuration-generation retry.
    validate_guest_cid(bar.read_u64(config_offset))
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

/// Device-lifetime TX ownership. A cached driver failure must retain this
/// pool until every published DMA chain has completed.
pub(crate) struct TxPool {
    queue: Rc<RefCell<Virtqueue>>,
    pages: Vec<IoBuf>,
    completions: Vec<WriteCompletion<Option<IoBuf>>>,
    drainer_waker: Option<std::task::LocalWaker>,
}

impl TxPool {
    /// Allocate the fixed data pages and all completion bookkeeping before
    /// the device can observe a TX descriptor.
    pub(crate) fn new(queue: Rc<RefCell<Virtqueue>>) -> IoResult<Self> {
        let queue_size = usize::from(queue.borrow().queue_size());
        if queue_size < 16 {
            return Err(ErrorKind::InvalidInput.into());
        }
        let page_count = ((queue_size - 8) / 2).min(64);
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(page_count)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let mut completions = Vec::new();
        completions
            .try_reserve_exact(queue_size)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for _ in 0..page_count {
            let page = IoBuf::new_from_size_align(PAGE_SIZE_SMALL as usize)
                .ok_or(ErrorKind::OutOfMemory)?;
            validate_payload_dma(page.capacity(), page.capacity(), page.phys_addr() as u64)?;
            pages.push(page);
        }
        Ok(Self {
            queue,
            pages,
            completions,
            drainer_waker: None,
        })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pages(&self) -> &[IoBuf] {
        &self.pages
    }

    /// Validate and synchronously publish one packet. Data pages remain owned
    /// here until `poll_reclaim_one` observes their DMA completion.
    pub(crate) fn try_submit(&mut self, raw: RawHeader, bytes: &[u8]) -> IoResult<()> {
        let payload_len = u32::try_from(bytes.len()).map_err(|_| ErrorKind::InvalidInput)?;
        if bytes.len() > PAGE_SIZE_SMALL as usize {
            return Err(ErrorKind::InvalidInput.into());
        }
        validate_tx_header(raw, payload_len)?;

        let payload = if bytes.is_empty() {
            None
        } else {
            let mut page = self.pages.pop().ok_or(ErrorKind::WouldBlock)?;
            page.set_len(bytes.len());
            <IoBuf as AsMut<[u8]>>::as_mut(&mut page).copy_from_slice(bytes);
            Some(page)
        };
        let completion = match try_post_tx(self.queue.clone(), raw, payload) {
            Ok(completion) => completion,
            Err((err, payload)) => {
                if let Some(page) = payload {
                    self.pages.push(page);
                }
                return Err(err);
            }
        };
        assert!(self.completions.len() < self.completions.capacity());
        self.completions.push(completion);
        if let Some(waker) = self.drainer_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    /// Reclaim one completed chain in any order. Pending polls register the
    /// same concrete local waker with every in-flight completion.
    pub(crate) fn poll_reclaim_one(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<IoResult<()>> {
        for index in 0..self.completions.len() {
            let ready = self.completions[index].vq_completion.do_poll(cx);
            if let std::task::Poll::Ready((page, result)) = ready {
                drop(self.completions.swap_remove(index));
                if let Some(page) = page {
                    assert!(self.pages.len() < self.pages.capacity());
                    self.pages.push(page);
                }
                return std::task::Poll::Ready(result.map(|_| ()));
            }
        }
        match &mut self.drainer_waker {
            Some(waker) => waker.clone_from(cx.local_waker()),
            None => self.drainer_waker = Some(cx.local_waker().clone()),
        }
        std::task::Poll::Pending
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.pages.len(), self.completions.len())
    }
}

pub(crate) struct RxCompletion {
    completion: VqCompletion<IoBuf>,
}

impl RxCompletion {
    pub(crate) fn head(&self) -> u16 {
        self.completion.chain_head()
    }

    /// Finish a completion selected by the ordered used-ring cursor. This must
    /// not wait: the cursor exposes only heads processed by the reclaimer.
    pub(crate) fn finish_ordered(
        mut self,
        ordered_head: u16,
    ) -> (IoBuf, Result<PacketHeader, DecodeError>) {
        assert_eq!(self.head(), ordered_head, "ordered vsock RX head mismatch");
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let std::task::Poll::Ready((mut payload, used_len)) = self.completion.do_poll(&mut cx)
        else {
            panic!("ordered vsock RX completion was not reclaimed")
        };
        let used_len = used_len.expect("vsock RX completion unexpectedly failed");
        let header = self.completion.read_header::<[u8; HEADER_LEN]>();
        let decoded = decode_packet(&header, used_len, payload.capacity());
        if let Ok(header) = decoded {
            payload.set_len(header.len as usize);
        }
        (payload, decoded)
    }
}

/// Try to publish one RX buffer without waiting. Rejection leaves the buffer
/// and queue unchanged; successful publication exposes no old payload bytes.
pub(crate) fn try_post_rx(
    queue: Rc<RefCell<Virtqueue>>,
    payload: IoBuf,
) -> std::result::Result<RxCompletion, (std::io::Error, IoBuf)> {
    try_post_rx_with_notification::<true>(queue, payload)
}

fn try_post_rx_with_notification<const NOTIFY: bool>(
    queue: Rc<RefCell<Virtqueue>>,
    mut payload: IoBuf,
) -> std::result::Result<RxCompletion, (std::io::Error, IoBuf)> {
    let payload_data = match validate_payload_dma(
        payload.capacity(),
        payload.capacity(),
        payload.phys_addr() as u64,
    ) {
        Ok(len) => UserData {
            phys_addr: payload.phys_addr() as u64,
            len,
        },
        Err(err) => return Err((err, payload)),
    };
    let (chain_head, header_data) = {
        let mut queue = queue.borrow_mut();
        let Some(chain_head) = queue.alloc_descriptor_chain(2) else {
            return Err((ErrorKind::WouldBlock.into(), payload));
        };
        let (header, phys_addr, _) = queue.get_buffer::<[u8; HEADER_LEN]>(chain_head);
        header.fill(0);
        (
            chain_head,
            UserData {
                phys_addr,
                len: HEADER_LEN as u32,
            },
        )
    };
    payload.set_len(0);
    let completion = if NOTIFY {
        Virtqueue::add_buffs(
            queue,
            &[header_data, payload_data],
            0,
            2,
            chain_head,
            payload,
        )
    } else {
        Virtqueue::add_buffs_deferred(
            queue,
            &[header_data, payload_data],
            0,
            2,
            chain_head,
            payload,
        )
    };
    Ok(RxCompletion { completion })
}

pub(crate) struct PreparedRxPool {
    queue: Rc<RefCell<Virtqueue>>,
    pages: Vec<IoBuf>,
    completions: Vec<RxCompletion>,
}

impl PreparedRxPool {
    /// Allocate and validate the fixed RX pool without publishing DMA.
    pub(crate) fn new(queue: Rc<RefCell<Virtqueue>>) -> IoResult<Self> {
        let queue_size = queue.borrow().queue_size();
        if queue_size < 2 {
            return Err(ErrorKind::InvalidInput.into());
        }
        let count = usize::from(queue_size / 2).min(64);
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(count)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        let mut completions = Vec::new();
        completions
            .try_reserve_exact(count)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for _ in 0..count {
            let page = IoBuf::new_from_size_align(PAGE_SIZE_SMALL as usize)
                .ok_or(ErrorKind::OutOfMemory)?;
            validate_payload_dma(page.capacity(), page.capacity(), page.phys_addr() as u64)?;
            pages.push(page);
        }
        Ok(Self {
            queue,
            pages,
            completions,
        })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pages(&self) -> &[IoBuf] {
        &self.pages
    }

    /// Claim the idle ordered cursor and publish every prepared page without
    /// notifying. All fallible memory work is complete and the fixed pool fits
    /// the queue; the caller kicks once after setting DRIVER_OK.
    pub(crate) fn publish_deferred(self) -> RxPool {
        let Self {
            queue,
            pages,
            mut completions,
        } = self;
        let ordered = Virtqueue::ordered_completions(queue.clone());
        for page in pages {
            let completion = match try_post_rx_with_notification::<false>(queue.clone(), page) {
                Ok(completion) => completion,
                Err((err, _)) => panic!("prepared vsock RX publication failed: {err}"),
            };
            completions.push(completion);
        }
        RxPool {
            queue,
            ordered,
            completions,
        }
    }
}

/// Fixed device-lifetime RX ownership. A later cached failure state must keep
/// this pool and its device alive; cancelling its task would drop DMA owners.
pub(crate) struct RxPool {
    queue: Rc<RefCell<Virtqueue>>,
    ordered: OrderedCompletions,
    completions: Vec<RxCompletion>,
}

impl RxPool {
    /// Consume one already-reclaimed packet in used-ring order, then repost
    /// its page. The callback is synchronous and cannot retain the DMA page.
    pub(crate) fn poll_consume<R>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        consume: impl FnOnce(Result<PacketHeader, DecodeError>, &[u8]) -> R,
    ) -> std::task::Poll<R> {
        let std::task::Poll::Ready(head) = self.ordered.poll_next(cx) else {
            return std::task::Poll::Pending;
        };
        let index = self
            .completions
            .iter()
            .position(|completion| completion.head() == head)
            .expect("ordered vsock RX head has no retained completion");
        let completion = self.completions.swap_remove(index);
        let (payload, decoded) = completion.finish_ordered(head);
        let result = consume(decoded, payload.as_ref());
        assert!(self.completions.len() < self.completions.capacity());
        let reposted = match try_post_rx(self.queue.clone(), payload) {
            Ok(completion) => completion,
            Err((err, _)) => panic!("vsock RX repost failed: {err}"),
        };
        self.completions.push(reposted);
        std::task::Poll::Ready(result)
    }
}

pub(crate) struct EventCompletion {
    completion: VqCompletion<()>,
}

impl EventCompletion {
    pub(crate) fn head(&self) -> u16 {
        self.completion.chain_head()
    }

    pub(crate) fn finish_ordered(mut self, ordered_head: u16) -> Result<Event, EventError> {
        assert_eq!(
            self.head(),
            ordered_head,
            "ordered vsock event head mismatch"
        );
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let std::task::Poll::Ready(((), used_len)) = self.completion.do_poll(&mut cx) else {
            panic!("ordered vsock event completion was not reclaimed")
        };
        let used_len = used_len.expect("vsock event completion unexpectedly failed");
        let bytes = self.completion.read_header::<[u8; EVENT_LEN]>();
        decode_event(&bytes, used_len)
    }
}

pub(crate) fn try_post_event(queue: Rc<RefCell<Virtqueue>>) -> IoResult<EventCompletion> {
    try_post_event_with_notification::<true>(queue)
}

fn try_post_event_with_notification<const NOTIFY: bool>(
    queue: Rc<RefCell<Virtqueue>>,
) -> IoResult<EventCompletion> {
    let (head, data) = {
        let mut queue = queue.borrow_mut();
        let Some(head) = queue.alloc_descriptor_chain(1) else {
            return Err(ErrorKind::WouldBlock.into());
        };
        let (event, phys_addr, _) = queue.get_buffer::<[u8; EVENT_LEN]>(head);
        event.fill(0);
        (
            head,
            UserData {
                phys_addr,
                len: EVENT_LEN as u32,
            },
        )
    };
    let completion = if NOTIFY {
        Virtqueue::add_buffs(queue, &[data], 0, 1, head, ())
    } else {
        Virtqueue::add_buffs_deferred(queue, &[data], 0, 1, head, ())
    };
    Ok(EventCompletion { completion })
}

pub(crate) struct PreparedEventPool {
    queue: Rc<RefCell<Virtqueue>>,
    count: usize,
    completions: Vec<EventCompletion>,
}

impl PreparedEventPool {
    pub(crate) fn new(queue: Rc<RefCell<Virtqueue>>) -> IoResult<Self> {
        let count = usize::from(queue.borrow().queue_size()).min(4);
        if count == 0 {
            return Err(ErrorKind::InvalidInput.into());
        }
        let mut completions = Vec::new();
        completions
            .try_reserve_exact(count)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Self {
            queue,
            count,
            completions,
        })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// Publish the initial event buffers without notifying; the caller kicks
    /// once after setting DRIVER_OK.
    pub(crate) fn publish_deferred(self) -> EventPool {
        let Self {
            queue,
            count,
            mut completions,
        } = self;
        let ordered = Virtqueue::ordered_completions(queue.clone());
        for _ in 0..count {
            completions.push(
                try_post_event_with_notification::<false>(queue.clone())
                    .unwrap_or_else(|err| panic!("prepared vsock event publication failed: {err}")),
            );
        }
        EventPool {
            queue,
            ordered,
            completions,
        }
    }
}

/// Device-lifetime event ownership; retain this with the device on failure.
pub(crate) struct EventPool {
    queue: Rc<RefCell<Virtqueue>>,
    ordered: OrderedCompletions,
    completions: Vec<EventCompletion>,
}

impl EventPool {
    pub(crate) fn poll_consume<R>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        consume: impl FnOnce(Result<Event, EventError>) -> R,
    ) -> std::task::Poll<R> {
        let std::task::Poll::Ready(head) = self.ordered.poll_next(cx) else {
            return std::task::Poll::Pending;
        };
        let index = self
            .completions
            .iter()
            .position(|completion| completion.head() == head)
            .expect("ordered vsock event head has no retained completion");
        let event = self.completions.swap_remove(index).finish_ordered(head);
        let result = consume(event);
        assert!(self.completions.len() < self.completions.capacity());
        self.completions.push(
            try_post_event(self.queue.clone())
                .unwrap_or_else(|err| panic!("vsock event repost failed: {err}")),
        );
        std::task::Poll::Ready(result)
    }
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
