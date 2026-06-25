//! moto-stats: a federated metrics protocol for Motor OS.
//!
//! Motor OS is a microkernel: statistics are produced by several mutually
//! independent components — the kernel, and userspace service processes such as
//! sys-io (later sys-io-fs / sys-io-net). Neither a syscall-only interface (the
//! kernel cannot see userspace producers) nor a procfs-style pseudo-filesystem
//! (the FS itself is a userspace service, and would create a dependency cycle)
//! can serve as a single, unified stats layer.
//!
//! Instead, each producer is identified by a stable `provider` id, and a
//! [`Collector`] aggregates them, choosing the right transport per provider: a
//! syscall (`SysRay`) for the kernel, and a synchronous IPC channel for userspace
//! services.
//!
//! Everything is **dynamically discovered** — this crate hardcodes no metric ids
//! and no provider set:
//!   * userspace providers register themselves (name + service URL) with a
//!     standalone registry daemon at the well-known URL [`REGISTRY_URL`]; the
//!     collector lists the registry to learn which providers exist;
//!   * each provider (including the kernel, over `SysRay`) describes its own
//!     metrics — ids, names, units — on request.
//!
//! A metric is addressed by the triple `(provider, metric, scope)`:
//!   * `provider` — which component produced it (a provider id == producing PID);
//!   * `metric`   — the metric id within that provider (provider-private);
//!   * `scope`    — a PID, or [`SCOPE_GLOBAL`] for provider-wide aggregates.
//!
//! The shared wire types ([`MetricEntry`], [`MetricDescWire`], [`Unit`]) are
//! defined in `moto-sys`, not here, because the kernel produces them directly
//! into user buffers via `SysRay` and cannot depend on this (IPC) crate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// Well-known provider ids. A provider id is the PID of the producing process
/// (`moto_sys::stats` already uses `PID_KERNEL == 1`), with 0 reserved for the
/// cross-provider aggregate. Only the kernel's id is fixed; userspace providers
/// register with their actual PID at runtime.
pub mod provider {
    /// Reserved: cross-provider aggregate ("System").
    pub const SYSTEM: u64 = 0;
    /// The kernel. Fixed because the kernel cannot register over IPC and is
    /// reached via syscall instead.
    pub const KERNEL: u64 = 1;
}

/// `scope` value for a provider-wide (not per-process) metric.
pub const SCOPE_GLOBAL: u64 = 0;

// ------------------------------- protocol ids ------------------------------- //

/// The well-known URL of the stats registry daemon (`sys-stats-reg`). The single
/// bootstrap constant of the whole protocol: everything else is discovered.
pub const REGISTRY_URL: &str = "moto-stats-registry";

/// Provider command: return the current value of every metric (paginated).
pub const CMD_QUERY_METRICS: u16 = 1;
/// Provider command: return the provider's metric descriptors (id, name, unit).
pub const CMD_DESCRIBE: u16 = 2;
/// Registry command: register the calling provider (name + service URL).
pub const CMD_REGISTER: u16 = 3;
/// Registry command: list all registered providers (paginated).
pub const CMD_LIST: u16 = 4;
/// Registry command: remove the calling provider's registration (identified by
/// its verified PID — a provider can only unregister itself).
pub const CMD_UNREGISTER: u16 = 5;

/// Maximum length of a provider/metric name on the wire (nul-padded). Matches
/// `moto_sys::stats::MAX_METRIC_NAME_LEN`.
pub const MAX_NAME_LEN: usize = 32;
/// Maximum length of a provider service URL on the wire (nul-padded).
pub const MAX_URL_LEN: usize = 48;

// ------- shared wire types (defined in moto-sys; re-exported for parity) ------ //

#[cfg(feature = "userspace")]
pub use moto_sys::stats::{MetricDescWire, MetricEntry};

// --------------------------- fixed-string helpers --------------------------- //

fn encode_fixed<const N: usize>(s: &str) -> [u8; N] {
    assert!(s.len() <= N);
    debug_assert!(s.is_ascii());

    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    let n = core::cmp::min(bytes.len(), N);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Encode a name into a nul-padded [`MAX_NAME_LEN`] array (truncating if needed).
pub fn encode_str(s: &str) -> [u8; MAX_NAME_LEN] {
    encode_fixed(s)
}

/// Encode a URL into a nul-padded [`MAX_URL_LEN`] array (truncating if needed).
pub fn encode_url(s: &str) -> [u8; MAX_URL_LEN] {
    encode_fixed(s)
}

/// Decode a nul-padded fixed byte array back into a string slice.
pub fn decode_fixed(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// A registered provider as stored by, and listed from, the registry (the
/// element type of the [`CMD_LIST`] response, and the payload of [`CMD_REGISTER`]).
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct ProviderRecord {
    pub provider_id: u64,
    pub name: [u8; MAX_NAME_LEN],
    pub url: [u8; MAX_URL_LEN],
}

const _: () = assert!(core::mem::size_of::<ProviderRecord>() == 88);

impl ProviderRecord {
    pub fn new(provider_id: u64, name: &str, url: &str) -> Self {
        Self {
            provider_id,
            name: encode_str(name),
            url: encode_url(url),
        }
    }
}

// --------------- byte (de)serialization of POD-array payloads --------------- //

/// Copy `items` into `dst` (a raw byte region, e.g. an IPC channel buffer past
/// its header). Returns the number written, which may be fewer than `items.len()`
/// if `dst` is too small. `T` must be a `#[repr(C)]` plain-old-data type.
pub fn encode_pods<T: Copy>(dst: &mut [u8], items: &[T]) -> usize {
    let sz = core::mem::size_of::<T>();
    let n = core::cmp::min(items.len(), dst.len() / sz);
    for (i, item) in items.iter().take(n).enumerate() {
        // SAFETY: bounds checked above; T is repr(C) POD. Write unaligned
        // because `dst` carries no alignment guarantee.
        unsafe {
            core::ptr::write_unaligned(dst.as_mut_ptr().add(i * sz) as *mut T, *item);
        }
    }
    n
}

/// Read `count` values of `T` from `src` (the inverse of [`encode_pods`]).
pub fn decode_pods<T: Copy>(src: &[u8], count: usize) -> Vec<T> {
    let sz = core::mem::size_of::<T>();
    let count = core::cmp::min(count, src.len() / sz);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: bounds checked above; T is POD; read unaligned.
        let item = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i * sz) as *const T) };
        out.push(item);
    }
    out
}

/// The maximum number of `T` values that fit in a byte region of `bytes` length
/// — useful for sizing a single RPC response.
pub const fn max_pods<T>(bytes: usize) -> usize {
    bytes / core::mem::size_of::<T>()
}

#[cfg(feature = "userspace")]
mod userspace;

#[cfg(feature = "userspace")]
pub use userspace::{
    respond_pods, Collector, MetricInfo, PagedRequest, PagedResponse, ProviderInfo,
    RegisterRequest, RegisterResponse,
};
