//! One synchronous request at a time, with authenticated peers and owned payloads.
use crate::config::Result;
use crate::control::{PAYLOAD_BYTES, VERSION};
use moto_sdk::ipc::sync::{ChannelSize, ClientConnection, LocalServerConnection};
use moto_sdk::rt::{self, time::Instant};
use moto_sdk::sys::{self, SysCpu, SysHandle, SysObj, caps};

pub fn own_caps() -> u64 {
    sys::ProcessStaticPage::get().capabilities
}

pub fn interactive(caps: u64) -> bool {
    caps::ProcessRole::from_caps(caps) == caps::ProcessRole::Interactive
}

pub fn require_interactive() -> Result<u64> {
    let caps = own_caps();
    if !interactive(caps) {
        return Err("requires the Interactive role");
    }
    Ok(caps)
}

pub fn require(caps: u64, required: u64) -> Result<()> {
    for (bit, error) in [
        (caps::CAP_NET, "requires CAP_NET"),
        (caps::CAP_FS_WRITE, "requires CAP_FS_WRITE"),
        (caps::CAP_SPAWN, "requires CAP_SPAWN"),
        (
            caps::CAP_SPAWN_DETACHED,
            "requires CAP_SPAWN_DETACHED; add wg-tool to spawn-detached in /user/cfg/rush.toml and start a new shell",
        ),
    ] {
        if required & bit != 0 && caps & bit == 0 {
            return Err(error);
        }
    }
    Ok(())
}

pub fn authenticate(handle: SysHandle, expected_pid: Option<u64>) -> Result<u64> {
    let pid = SysObj::get_pid(handle).map_err(|_| "cannot authenticate peer PID")?;
    let caps =
        SysObj::get_capabilities(handle).map_err(|_| "cannot authenticate peer capabilities")?;
    if pid == 0
        || expected_pid.is_some_and(|expected| expected != pid)
        || !interactive(caps)
        || caps & caps::CAP_NET == 0
    {
        return Err("control peer has an unexpected PID, role or capabilities");
    }
    Ok(caps)
}

pub fn deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(5)
}

pub async fn until<T>(
    future: impl std::future::Future<Output = Result<T>>,
    deadline: Option<Instant>,
) -> Result<T> {
    let Some(deadline) = deadline else {
        return future.await;
    };
    let mut future = std::pin::pin!(future);
    let mut timer = std::pin::pin!(moto_sdk::async_runtime::sleep(
        deadline.duration_since(Instant::now())
    ));
    std::future::poll_fn(|cx| {
        if Instant::now() >= deadline || timer.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err("startup deadline expired"));
        }
        future.as_mut().poll(cx)
    })
    .await
}

fn message(bytes: &[u8]) -> Result<(u16, Vec<u8>)> {
    // Copy the shared input once before interpreting any lengths or fields.
    let bytes = bytes[8..].to_vec();
    let code = u16::from_le_bytes(bytes[..2].try_into().unwrap());
    if u16::from_le_bytes(bytes[2..4].try_into().unwrap()) != VERSION
        || bytes[4..8] != [0; 4]
        || bytes[12..16] != [0; 4]
    {
        return Err("unsupported control version or flags");
    }
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if length > PAYLOAD_BYTES {
        return Err("control payload exceeds channel");
    }
    Ok((code, bytes[16..16 + length].to_vec()))
}

fn write(bytes: &mut [u8], code: u16, payload: &[u8]) -> Result<()> {
    if payload.len() > PAYLOAD_BYTES {
        return Err("control payload exceeds channel");
    }
    // Preserve the IPC sequence word, initialize every other response byte.
    bytes[8..].fill(0);
    bytes[8..10].copy_from_slice(&code.to_le_bytes());
    bytes[10..12].copy_from_slice(&VERSION.to_le_bytes());
    bytes[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes[24..24 + payload.len()].copy_from_slice(payload);
    Ok(())
}

pub fn request(connection: &LocalServerConnection) -> Result<(u16, Vec<u8>)> {
    message(connection.data())
}

pub fn respond(connection: &mut LocalServerConnection, status: u16, payload: &[u8]) -> Result<()> {
    write(connection.data_mut(), status, payload)?;
    connection
        .finish_rpc()
        .map_err(|_| "control client disconnected before acknowledgment")
}

pub struct Connection(pub ClientConnection);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.disconnect();
    }
}
impl Connection {
    pub fn open(url: &str, pid: u64) -> std::result::Result<Option<(Self, u64)>, String> {
        let mut connection = Self(
            ClientConnection::new(ChannelSize::Small)
                .map_err(|code| format!("cannot allocate IPC channel ({code})"))?,
        );
        match connection.0.connect(url) {
            Ok(()) => (),
            Err(rt::E_NOT_FOUND) => return Ok(None),
            Err(code) => return Err(format!("cannot connect to control endpoint ({code})")),
        }
        let caps = authenticate(connection.0.handle(), Some(pid))?;
        Ok(Some((connection, caps)))
    }

    pub fn rpc(&mut self, command: u16, payload: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        if Instant::now() >= deadline {
            self.0.disconnect();
            return Err("control deadline expired");
        }
        write(self.0.data_mut(), command, payload)?;
        if let Err(code) = self.0.do_rpc(Some(deadline)) {
            self.0.disconnect();
            return Err(if code == rt::E_TIMED_OUT {
                "control deadline expired"
            } else {
                "control connection failed"
            });
        }
        let (status, payload) = message(self.0.data())?;
        match status {
            rt::E_OK => Ok(payload),
            rt::E_NOT_ALLOWED => Err("control request denied"),
            rt::E_INVALID_ARGUMENT => Err("invalid control request or peer index"),
            _ => Err("daemon operation failed"),
        }
    }
}

pub struct Handle(pub SysHandle);
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = SysObj::put(self.0);
    }
}

/// Startup needs a deadline while LocalServer waits for its first connection.
/// This one-shot timer is unrelated to control-client lifetime or discovery.
pub fn alarm(deadline: Instant) -> Result<Handle> {
    let (ring, wait) = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0)
        .map_err(|_| "cannot create startup timer")?;
    let ring = Handle(ring);
    let wait = Handle(wait);
    std::thread::Builder::new()
        .name("wg:startup-deadline".into())
        .spawn(move || {
            std::thread::sleep(deadline.duration_since(Instant::now()));
            let _ = SysCpu::wake(ring.0);
            drop(ring);
        })
        .map_err(|_| "cannot start startup timer")?;
    Ok(wait)
}
