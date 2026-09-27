//! Exercise the real server with deterministic syscall outcomes.
extern crate alloc;
extern crate self as moto_rt;
extern crate self as moto_sys;

use std::cell::RefCell;
use std::collections::BTreeSet;

pub type ErrorCode = u16;
pub const E_INVALID_ARGUMENT: ErrorCode = 1;
pub const E_BAD_HANDLE: ErrorCode = 2;
pub const E_TIMED_OUT: ErrorCode = 3;
pub const E_OUT_OF_MEMORY: ErrorCode = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SysHandle(u64);
impl SysHandle {
    pub const NONE: Self = Self(0);
    pub const SELF: Self = Self(u64::MAX);
}

pub mod time {
    pub use std::time::Instant;
}
pub mod sys_mem {
    pub const PAGE_SIZE_SMALL: u64 = 4096;
    pub const PAGE_SIZE_MID: u64 = 2097152;
}
pub fn url_encode(url: &str) -> String {
    url.to_owned()
}

#[derive(Default)]
struct Kernel {
    next_handle: u64,
    handles: BTreeSet<SysHandle>,
    mappings: BTreeSet<u64>,
    refuse: bool,
    mapping_limit: Option<usize>,
    lost_name: bool,
    reply: Option<(Vec<SysHandle>, Result<(), ErrorCode>)>,
    timeout: Option<time::Instant>,
}
thread_local! {
    static KERNEL: RefCell<Kernel> = RefCell::new(Kernel::default());
}

pub struct SysMem;
impl SysMem {
    pub const F_READABLE: u32 = 1;
    pub const F_WRITABLE: u32 = 2;
    // A real page, so that a test can put a request header in it.
    pub fn map(_: SysHandle, _: u32, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ErrorCode> {
        KERNEL.with_borrow_mut(|kernel| {
            if kernel.refuse || kernel.mapping_limit == Some(kernel.mappings.len()) {
                return Err(E_OUT_OF_MEMORY);
            }
            let page: &'static mut [u64; 512] = Box::leak(Box::new([0; 512]));
            let address = page.as_mut_ptr() as u64;
            assert!(kernel.mappings.insert(address));
            Ok(address)
        })
    }
    pub fn unmap(_: SysHandle, _: u32, _: u64, address: u64) -> Result<(), ErrorCode> {
        KERNEL.with_borrow_mut(|kernel| assert!(kernel.mappings.remove(&address)));
        Ok(())
    }
}

pub struct SysObj;
impl SysObj {
    pub fn create(_: SysHandle, _: u32, _: &str) -> Result<SysHandle, ErrorCode> {
        KERNEL.with_borrow_mut(|kernel| {
            kernel.next_handle += 1;
            let handle = SysHandle(kernel.next_handle);
            assert!(kernel.handles.insert(handle));
            Ok(handle)
        })
    }
    pub fn get(_: SysHandle, _: u32, _: &str) -> Result<SysHandle, ErrorCode> {
        unreachable!("these tests exercise server endpoints")
    }
    pub fn put(handle: SysHandle) -> Result<(), ErrorCode> {
        KERNEL.with_borrow_mut(|kernel| {
            assert!(kernel.handles.remove(&handle));
            kernel.lost_name |= kernel.handles.is_empty();
        });
        Ok(())
    }
}

pub struct SysCpu;
impl SysCpu {
    pub fn wait(
        handles: &mut [SysHandle],
        _: SysHandle,
        _: SysHandle,
        timeout: Option<time::Instant>,
    ) -> Result<(), ErrorCode> {
        KERNEL.with_borrow_mut(|kernel| {
            kernel.timeout = timeout;
            let (wakers, result) = kernel.reply.take().expect("missing syscall outcome");
            assert!(wakers.iter().all(|handle| handles.contains(handle)));
            handles.fill(SysHandle::NONE);
            handles[..wakers.len()].copy_from_slice(&wakers);
            result
        })
    }
    pub fn wake(_: SysHandle) -> Result<(), ErrorCode> {
        Ok(())
    }
}

#[allow(dead_code)]
#[path = "../sys/lib/moto-ipc/src/sync.rs"]
mod sync;
use sync::{ChannelSize, LocalServer};

fn reply(wakers: &[u64], result: Result<(), ErrorCode>) {
    KERNEL.with_borrow_mut(|kernel| {
        assert!(kernel.reply.is_none());
        kernel.reply = Some((wakers.iter().copied().map(SysHandle).collect(), result));
    });
}

#[test]
fn timeout_delivers_active_listener_and_extra_wakes() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 3, 2).unwrap();
    reply(&[1], Ok(()));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Ok(vec![SysHandle(1)]));
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);

    // The kernel acknowledges these wakes even when the timer fired too.
    reply(&[1, 2, 99], Err(E_TIMED_OUT));
    assert_eq!(
        server.wait(SysHandle::NONE, &[SysHandle(99)]),
        Ok(vec![SysHandle(1), SysHandle(2), SysHandle(99)])
    );
    assert!(server.get_connection(SysHandle(1)).unwrap().connected());
    assert!(server.get_connection(SysHandle(2)).unwrap().connected());
    assert!(KERNEL.with_borrow(|kernel| kernel.timeout.is_some()));
}

#[test]
fn timeout_without_wakes_returns_empty() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 1).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);
    reply(&[], Err(E_TIMED_OUT));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Ok(vec![]));
    assert!(server.get_connection(SysHandle(1)).unwrap().connected());
}

#[test]
fn refused_refill_still_reports_closed_connections() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 1).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);
    reply(&[1], Err(E_BAD_HANDLE));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Err(vec![SysHandle(1)]));
    assert!(server.get_connection(SysHandle(1)).is_none());
}

struct Extension(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for Extension {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn disconnected_pair() -> (LocalServer, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 2).unwrap();
    reply(&[1, 2], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for handle in [SysHandle(1), SysHandle(2)] {
        let connection = server.get_connection(handle).unwrap();
        connection.set_extension(Box::new(Extension(dropped.clone())));
        connection.disconnect();
    }
    (server, dropped)
}

#[test]
fn retired_memory_is_available_to_the_next_refill() {
    let (mut server, dropped) = disconnected_pair();
    // Only retiring the old mappings makes room for replacement listeners.
    KERNEL.with_borrow_mut(|kernel| kernel.mapping_limit = Some(2));
    reply(&[], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 2);
    KERNEL.with_borrow(|kernel| {
        assert_eq!(kernel.handles, BTreeSet::from([SysHandle(3), SysHandle(4)]));
        assert_eq!(kernel.mappings.len(), 2);
        assert!(!kernel.lost_name);
    });
    drop(server);
    KERNEL.with_borrow(|kernel| {
        assert!(kernel.handles.is_empty());
        assert!(kernel.mappings.is_empty());
    });
}

#[test]
fn refused_refills_keep_one_handle_without_retired_memory() {
    let (mut server, dropped) = disconnected_pair();
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);
    for _ in 0..3 {
        reply(&[], Err(E_TIMED_OUT));
        assert_eq!(server.wait(SysHandle::NONE, &[]), Ok(vec![]));
        KERNEL.with_borrow(|kernel| {
            assert_eq!(kernel.handles.len(), 1);
            assert!(kernel.mappings.is_empty());
            assert!(!kernel.lost_name);
        });
        assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
    drop(server);
    assert!(KERNEL.with_borrow(|kernel| kernel.handles.is_empty()));
}

#[test]
fn bad_active_and_listening_peers_release_their_mappings() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 3, 2).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);
    reply(&[1, 2], Err(E_BAD_HANDLE));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Err(vec![SysHandle(1)]));
    KERNEL.with_borrow(|kernel| {
        assert!(kernel.mappings.is_empty());
        assert_eq!(kernel.handles.len(), 1);
        assert!(!kernel.lost_name);
    });
}

#[test]
fn a_live_endpoint_releases_the_retired_handle_during_refusal() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 2).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    server.get_connection(SysHandle(1)).unwrap().disconnect();
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);
    reply(&[], Err(E_TIMED_OUT));
    server.wait(SysHandle::NONE, &[]).unwrap();
    KERNEL.with_borrow(|kernel| {
        assert_eq!(kernel.handles, BTreeSet::from([SysHandle(2)]));
        assert_eq!(kernel.mappings.len(), 1);
        assert!(!kernel.lost_name);
    });
}

#[test]
fn refused_refill_arms_a_timer_until_memory_recovers() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 1).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    KERNEL.with_borrow_mut(|kernel| kernel.refuse = true);
    reply(&[], Err(E_TIMED_OUT));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Ok(vec![]));
    KERNEL.with_borrow(|kernel| {
        assert!(
            kernel.timeout.is_some(),
            "refused refill did not arm a timer"
        );
        assert_eq!(kernel.handles, BTreeSet::from([SysHandle(1)]));
    });

    KERNEL.with_borrow_mut(|kernel| kernel.refuse = false);
    // The timer returned us to the caller without an existing client's wake.
    // Its next wait refills the pool, so a new client can then wake handle 2.
    reply(&[2], Ok(()));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Ok(vec![SysHandle(2)]));
    assert!(server.get_connection(SysHandle(2)).unwrap().connected());
    assert!(KERNEL.with_borrow(|kernel| kernel.timeout.is_none()));
}

#[test]
fn a_disconnected_connection_has_no_request() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 1).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    let connection = server.get_connection(SysHandle(1)).unwrap();
    // The header's sequence number is the page's first word; one is the
    // client's first request.
    connection.data_mut()[..8].copy_from_slice(&1_u64.to_ne_bytes());
    assert!(connection.have_req());
    connection.disconnect();
    // Reset to expect sequence one, the page still says one: not a request.
    assert!(!connection.have_req());
}

#[test]
fn a_changed_request_sequence_disconnects_without_panicking() {
    let mut server = LocalServer::new("test", ChannelSize::Small, 2, 1).unwrap();
    reply(&[1], Ok(()));
    server.wait(SysHandle::NONE, &[]).unwrap();
    let connection = server.get_connection(SysHandle(1)).unwrap();
    connection.data_mut()[..8].copy_from_slice(&1_u64.to_ne_bytes());
    assert!(connection.have_req());

    // The client owns the page and can change it while the server prepares a reply.
    connection.data_mut()[..8].copy_from_slice(&3_u64.to_ne_bytes());
    assert_eq!(connection.finish_rpc(), Err(E_INVALID_ARGUMENT));
    assert!(!connection.connected());

    reply(&[], Ok(()));
    assert_eq!(server.wait(SysHandle::NONE, &[]), Ok(vec![]));
    assert!(server.get_connection(SysHandle(1)).is_none());
}
