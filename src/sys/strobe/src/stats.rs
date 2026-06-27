//! The Motor OS stats registry daemon.
//!
//! A standalone service hosting the well-known [`moto_stats::REGISTRY_URL`]
//! endpoint. Userspace stats providers register themselves here on startup
//! (`CMD_REGISTER`); a collector lists the registry (`CMD_LIST`) to discover
//! which providers exist, then talks to each provider directly. This is the
//! mechanism that makes provider discovery dynamic — the kernel object namespace
//! has no enumeration operation, so the registry stands in for it.
//!
//! The registry is the single piece of well-known wiring; everything else
//! (provider set, metric names, units) is discovered at runtime.

use moto_ipc::sync::*;
use moto_stats::{PagedRequest, ProviderRecord, RegisterRequest, RegisterResponse};
use moto_sys::{SysHandle, SysObj};

pub struct Registry {
    server: LocalServer,
    /// Registered providers, keyed by `provider_id` (one record per provider).
    providers: Vec<ProviderRecord>,
}

impl Registry {
    pub fn new() -> Self {
        let server = LocalServer::new(moto_stats::REGISTRY_URL, ChannelSize::Small, 16, 2)
            .expect("sys-stats-reg: failed to create registry endpoint");
        Registry {
            server,
            providers: Vec::new(),
        }
    }

    fn process(&mut self, waker: SysHandle) {
        let Registry { server, providers } = self;

        let Some(conn) = server.get_connection(waker) else {
            return;
        };
        if !conn.connected() || !conn.have_req() {
            return;
        }

        let cmd = unsafe { conn.raw_channel().get::<RequestHeader>().cmd };

        match cmd {
            moto_stats::CMD_REGISTER => {
                // Copy the requested record out before touching the response,
                // then stamp the *verified* PID of the connecting process (the
                // peer of this connection) over whatever id the client claimed.
                let mut record = unsafe { conn.raw_channel().get::<RegisterRequest>().record };
                if let Ok(pid) = SysObj::get_pid(conn.handle()) {
                    record.provider_id = pid;
                }

                if let Some(existing) = providers
                    .iter_mut()
                    .find(|r| r.provider_id == record.provider_id)
                {
                    *existing = record;
                } else {
                    providers.push(record);
                }

                log::debug!(
                    "sys-stats-reg: registered provider '{}' (id {}) at '{}'",
                    moto_stats::decode_fixed(&record.name),
                    record.provider_id,
                    moto_stats::decode_fixed(&record.url),
                );

                unsafe {
                    conn.raw_channel()
                        .get_mut::<RegisterResponse>()
                        .header
                        .result = moto_rt::E_OK;
                }
            }
            moto_stats::CMD_UNREGISTER => {
                // Drop the calling provider's record, identified by its verified
                // peer PID (a provider can only unregister itself). Idempotent:
                // dropping a record that isn't there still succeeds.
                let result = match SysObj::get_pid(conn.handle()) {
                    Ok(pid) => {
                        let before = providers.len();
                        providers.retain(|r| r.provider_id != pid);
                        if providers.len() != before {
                            log::debug!("sys-stats-reg: unregistered provider id {pid}");
                        }
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                };
                unsafe {
                    conn.raw_channel().get_mut::<ResponseHeader>().result = result;
                }
            }
            moto_stats::CMD_LIST => {
                let start_index = unsafe { conn.raw_channel().get::<PagedRequest>().start_index };
                moto_stats::respond_pods(conn.data_mut(), providers, start_index);
            }
            _ => unsafe {
                conn.raw_channel().get_mut::<ResponseHeader>().result = moto_rt::E_INVALID_ARGUMENT;
            },
        }

        let _ = conn.finish_rpc();
    }

    pub fn run(&mut self) -> ! {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(20));
            if moto_log::init("strobe-stats").is_ok() {
                log::set_max_level(log::LevelFilter::Info);
                break;
            }
        }

        loop {
            match self.server.wait(SysHandle::NONE, &[]) {
                Ok(wakers) => {
                    for waker in wakers {
                        self.process(waker);
                    }
                }
                // Dropped connections are cleaned up by wait(); records persist
                // (a collector simply fails to reach a dead provider and skips it).
                Err(_dropped) => {}
            }
        }
    }
}
