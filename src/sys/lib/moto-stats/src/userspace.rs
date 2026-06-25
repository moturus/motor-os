//! Userspace transport: synchronous-IPC framing, the provider/registry response
//! helper, and the [`Collector`] client (which discovers userspace providers via
//! the registry daemon and the kernel via `SysRay`). Gated behind `userspace`.

use super::*;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use moto_ipc::sync::{ChannelSize, ClientConnection, RequestHeader, ResponseHeader};
use moto_rt::ErrorCode;
use moto_sys::SysRay;

/// Request for any paginated IPC command (`CMD_QUERY_METRICS`, `CMD_DESCRIBE`,
/// `CMD_LIST`): "give me entries starting at `start_index`".
#[repr(C, align(8))]
pub struct PagedRequest {
    pub header: RequestHeader,
    pub start_index: u32,
    pub _reserved: u32,
}

/// Response header for any paginated IPC command; immediately followed by
/// `num_entries` POD elements (their type depends on the command).
#[repr(C, align(8))]
pub struct PagedResponse {
    pub header: ResponseHeader,
    /// Number of elements returned in this response.
    pub num_entries: u32,
    /// Total number of elements the server currently has (for pagination).
    pub total_entries: u32,
}

/// Request for `CMD_REGISTER`: the provider's record (`provider_id` is advisory;
/// the registry stamps the verified PID of the calling process).
#[repr(C, align(8))]
pub struct RegisterRequest {
    pub header: RequestHeader,
    pub record: ProviderRecord,
}

/// Response for `CMD_REGISTER`: the result is carried in the header.
#[repr(C, align(8))]
pub struct RegisterResponse {
    pub header: ResponseHeader,
}

// -------------------------------- server side -------------------------------- //

/// Fill a server's sync-channel response buffer with `all` (a POD slice),
/// honoring the requested `start_index`. Used by providers (for `CMD_QUERY_METRICS`
/// and `CMD_DESCRIBE`) and by the registry (for `CMD_LIST`).
///
/// `buf` is the whole channel data region (`conn.data_mut()`). The
/// channel-managed `header.seq` is deliberately left untouched.
pub fn respond_pods<T: Copy>(buf: &mut [u8], all: &[T], start_index: u32) {
    let header_sz = core::mem::size_of::<PagedResponse>();
    let total = all.len() as u32;
    let start = (start_index as usize).min(all.len());

    let written = if buf.len() > header_sz {
        encode_pods(&mut buf[header_sz..], &all[start..])
    } else {
        0
    };

    // SAFETY: `buf` is the channel buffer (a full page); PagedResponse starts at
    // offset 0 and fits. We only assign the public payload fields, never `seq`.
    let resp = unsafe { &mut *(buf.as_mut_ptr() as *mut PagedResponse) };
    resp.header.result = moto_rt::E_OK;
    resp.header.ver = 0;
    resp.num_entries = written as u32;
    resp.total_entries = total;
}

// -------------------------------- client side -------------------------------- //

/// A discovered provider: its id, human name, and service URL. An empty `url`
/// denotes the kernel, which is reached via `SysRay` rather than IPC.
#[derive(Clone, Debug)]
pub struct ProviderInfo {
    pub id: u64,
    pub name: String,
    pub url: String,
}

impl ProviderInfo {
    /// True if this is the kernel provider (syscall transport, no IPC endpoint).
    pub fn is_kernel(&self) -> bool {
        self.url.is_empty()
    }
}

/// A discovered metric: its id within its provider and its human name.
#[derive(Clone, Debug)]
pub struct MetricInfo {
    pub id: u32,
    pub name: String,
}

/// Aggregates metrics from providers, discovering userspace providers through
/// the registry daemon and the kernel through `SysRay`, and choosing the
/// transport per provider.
pub struct Collector;

impl Collector {
    /// The synthetic kernel provider (always present; `SysRay` transport).
    pub fn kernel() -> ProviderInfo {
        ProviderInfo {
            id: provider::KERNEL,
            name: "kernel".to_string(),
            url: String::new(),
        }
    }

    /// Every provider currently known: the kernel, plus all userspace providers
    /// registered with the registry. If the registry is unreachable, only the
    /// kernel is returned (best effort — discovery never hard-fails a listing).
    pub fn providers() -> Vec<ProviderInfo> {
        let mut out = vec![Self::kernel()];
        if let Ok(records) = Self::list_registry() {
            for r in records {
                if r.provider_id == provider::KERNEL {
                    continue; // The kernel is the syscall provider, added above.
                }
                out.push(ProviderInfo {
                    id: r.provider_id,
                    name: decode_fixed(&r.name).to_string(),
                    url: decode_fixed(&r.url).to_string(),
                });
            }
        }
        out
    }

    /// Find a provider by name (matches [`Collector::providers`]).
    pub fn provider_by_name(name: &str) -> Option<ProviderInfo> {
        Self::providers().into_iter().find(|p| p.name == name)
    }

    /// Describe the metrics a provider exposes (id, name, unit).
    pub fn describe(p: &ProviderInfo) -> Result<Vec<MetricInfo>, ErrorCode> {
        let wire = if p.is_kernel() {
            Self::describe_kernel()?
        } else {
            Self::paged_client::<MetricDescWire>(&p.url, CMD_DESCRIBE)?
        };
        Ok(wire
            .into_iter()
            .map(|d| MetricInfo {
                id: d.metric,
                name: d.name_str().to_string(),
            })
            .collect())
    }

    /// Read every metric value a provider currently exposes (provider-wide /
    /// aggregate scope).
    pub fn query(p: &ProviderInfo) -> Result<Vec<MetricEntry>, ErrorCode> {
        Self::query_scoped(p, SCOPE_GLOBAL)
    }

    /// Read a provider's metric values for a specific `scope` (a PID, or
    /// [`SCOPE_GLOBAL`]). Userspace IPC providers currently ignore `scope` (they
    /// expose only global metrics); the kernel honors it (per-process metrics).
    pub fn query_scoped(p: &ProviderInfo, scope: u64) -> Result<Vec<MetricEntry>, ErrorCode> {
        if p.is_kernel() {
            Self::query_kernel(scope)
        } else {
            Self::paged_client(&p.url, CMD_QUERY_METRICS)
        }
    }

    /// Read a single metric value at `scope`.
    pub fn read(p: &ProviderInfo, metric: u32, scope: u64) -> Result<u64, ErrorCode> {
        Self::query_scoped(p, scope)?
            .iter()
            .find(|e| e.metric == metric && e.scope == scope)
            .map(|e| e.value)
            .ok_or(moto_rt::E_NOT_FOUND)
    }

    /// Register the calling process as a stats provider with the registry. The
    /// `url` is the sync-RPC endpoint the process serves metrics on. Idempotent:
    /// re-registering updates the existing record.
    pub fn register(name: &str, url: &str) -> Result<(), ErrorCode> {
        let mut conn = ClientConnection::new(ChannelSize::Small)?;
        conn.connect(REGISTRY_URL)?;

        {
            let req = conn.req::<RegisterRequest>();
            req.header.cmd = CMD_REGISTER;
            req.header.ver = 0;
            req.header.flags = 0;
            req.record = ProviderRecord::new(moto_sys::current_pid(), name, url);
        }

        conn.do_rpc(None)?;

        let result = conn.resp::<RegisterResponse>().header.result;
        if result == moto_rt::E_OK {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// Remove the calling process's provider registration from the registry
    /// (the inverse of [`Collector::register`]). The registry identifies the
    /// record to drop by the caller's verified PID, so a process can only
    /// unregister itself. Idempotent: succeeds even if not currently registered.
    pub fn unregister() -> Result<(), ErrorCode> {
        let mut conn = ClientConnection::new(ChannelSize::Small)?;
        conn.connect(REGISTRY_URL)?;

        {
            let req = conn.req::<RequestHeader>();
            req.cmd = CMD_UNREGISTER;
            req.ver = 0;
            req.flags = 0;
        }

        conn.do_rpc(None)?;

        let result = conn.resp::<ResponseHeader>().result;
        if result == moto_rt::E_OK {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// Kernel provider: metric values for `scope`, read via `SysRay`. The kernel
    /// needs no other changes — it is the authority for its own metric set.
    fn query_kernel(scope: u64) -> Result<Vec<MetricEntry>, ErrorCode> {
        let mut cap = 64usize;
        loop {
            let mut buf = vec![MetricEntry::default(); cap];
            let (written, total) = SysRay::query_stats(scope, &mut buf)?;
            if total > cap {
                cap = total; // Buffer was too small; size to total and retry.
                continue;
            }
            buf.truncate(written);
            return Ok(buf);
        }
    }

    /// Kernel provider: metric descriptors, read via `SysRay`.
    fn describe_kernel() -> Result<Vec<MetricDescWire>, ErrorCode> {
        let mut cap = 64usize;
        loop {
            let zero = MetricDescWire {
                metric: 0,
                _reserved: 0,
                name: [0u8; MAX_NAME_LEN],
            };
            let mut buf = vec![zero; cap];
            let (written, total) = SysRay::query_stats_describe(&mut buf)?;
            if total > cap {
                cap = total;
                continue;
            }
            buf.truncate(written);
            return Ok(buf);
        }
    }

    /// The list of registered providers, fetched from the registry daemon.
    fn list_registry() -> Result<Vec<ProviderRecord>, ErrorCode> {
        Self::paged_client(REGISTRY_URL, CMD_LIST)
    }

    /// Drive a paginated request/response loop against `url`, collecting every
    /// `T` element the server returns.
    fn paged_client<T: Copy>(url: &str, cmd: u16) -> Result<Vec<T>, ErrorCode> {
        let mut conn = ClientConnection::new(ChannelSize::Small)?;
        conn.connect(url)?;

        let header_sz = core::mem::size_of::<PagedResponse>();
        let mut out = Vec::new();
        let mut start_index = 0u32;

        loop {
            {
                let req = conn.req::<PagedRequest>();
                req.header.cmd = cmd;
                req.header.ver = 0;
                req.header.flags = 0;
                req.start_index = start_index;
                req._reserved = 0;
            }

            conn.do_rpc(None)?;

            let (num, total) = {
                let resp = conn.resp::<PagedResponse>();
                if resp.header.result != moto_rt::E_OK {
                    return Err(resp.header.result);
                }
                (resp.num_entries as usize, resp.total_entries)
            };

            out.append(&mut decode_pods::<T>(&conn.data()[header_sz..], num));

            start_index += num as u32;
            if num == 0 || start_index >= total {
                break;
            }
        }

        Ok(out)
    }
}
