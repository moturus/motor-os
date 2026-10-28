//! Provisional detached startup, acknowledged over a private synchronous channel.
use crate::config::{Config, Result};
use crate::control::*;
use crate::motor_ipc::{self as ipc, Connection};
use moto_sdk::ipc::sync::{ChannelSize, LocalServer};
use moto_sdk::rt::{self, time::Instant};
use moto_sdk::sys::{self, SysHandle, caps};
use std::path::Path;
use std::process::{Child, Command, Stdio};

const DAEMON_CAPS: u64 = caps::CAP_INTERACTIVE | caps::CAP_NET;

pub struct Startup {
    connection: Connection,
    pub deadline: Instant,
}
impl Startup {
    fn connect(url: &str, parent: u64, deadline: Instant) -> Result<Self> {
        if ipc::own_caps() != DAEMON_CAPS {
            return Err("managed daemon has unexpected capabilities");
        }
        let (mut connection, caps) = Connection::open(url, parent)
            .map_err(|_| "cannot authenticate startup launcher")?
            .ok_or("startup launcher has exited")?;
        ipc::require(caps, caps::CAP_SPAWN | caps::CAP_SPAWN_DETACHED)?;
        if !connection.rpc(HELLO, &[], deadline)?.is_empty() {
            return Err("invalid startup acknowledgment");
        }
        Ok(Self {
            connection,
            deadline,
        })
    }

    pub fn ready(mut self, interface: &Interface) -> Result<()> {
        if !self
            .connection
            .rpc(READY, &interface.encode()?, self.deadline)?
            .is_empty()
        {
            return Err("invalid readiness acknowledgment");
        }
        // Ownership transfers at ACK. A lost final receipt is uncertain for the
        // launcher, but must not undo an already acknowledged activation.
        let _ = self.connection.rpc(COMMITTED, &[], self.deadline);
        Ok(())
    }

    fn fail(&mut self, stage: u16) {
        let _ = self
            .connection
            .rpc(START_ERROR, &stage.to_le_bytes(), self.deadline);
    }
}

pub fn daemon(args: &[String]) -> Result<()> {
    let caps = ipc::require_interactive()?;
    ipc::require(caps, caps::CAP_NET)?;
    let (path, mut startup) = match args {
        [path] => (path, None),
        [mode, url, parent, deadline, path] if mode == "--managed" => {
            let parent = parent.parse().map_err(|_| "invalid launcher PID")?;
            let deadline =
                Instant::from_u64(deadline.parse().map_err(|_| "invalid startup deadline")?);
            if deadline <= Instant::now() || deadline > ipc::deadline() {
                return Err("invalid startup deadline");
            }
            (path, Some(Startup::connect(url, parent, deadline)?))
        }
        _ => return Err("usage: wg FILE"),
    };
    let loaded = crate::motor_files::absolute(Path::new(path)).and_then(|path| {
        let document = crate::motor_files::read_until(
            Path::new(&path),
            startup.as_ref().map(|startup| startup.deadline),
        )?;
        Config::parse(&document.text).map(|config| (path, config))
    });
    let (path, config) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            if let Some(startup) = &mut startup {
                startup.fail(1);
            }
            return Err(error);
        }
    };
    let result = crate::motor::run(&config, &path, &mut startup);
    if let Some(startup) = &mut startup {
        startup.fail(2);
    }
    result
}

pub fn up(path: &str) -> std::result::Result<(u64, Interface), String> {
    let own = ipc::require_interactive()?;
    ipc::require(
        own,
        caps::CAP_NET | caps::CAP_SPAWN | caps::CAP_SPAWN_DETACHED,
    )?;
    let path = crate::motor_files::absolute(Path::new(path))?;
    let deadline = ipc::deadline();
    let mut nonce = [0u8; 16];
    rt::fill_random_bytes(&mut nonce);
    let url = format!(
        "wg-start-{}-{}",
        sys::current_pid(),
        nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut server = LocalServer::new(&url, ChannelSize::Small, 1, 1)
        .map_err(|_| "cannot create startup endpoint")?;
    let alarm = ipc::alarm(deadline)?;
    let mut child = Command::new("/system/bin/wg")
        .args([
            "--managed",
            &url,
            &sys::current_pid().to_string(),
            &deadline.as_u64().to_string(),
            &path,
        ])
        .env_clear()
        .env(caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{DAEMON_CAPS:x}"))
        .env(caps::MOTOR_OS_DETACHED_ENV_KEY, "true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "cannot spawn detached wg")?;
    let pid = u64::from(child.id());
    await_startup(&mut server, &mut child, &alarm, deadline).map(|interface| (pid, interface))
}

pub(super) fn await_startup(
    server: &mut LocalServer,
    child: &mut Child,
    alarm: &ipc::Handle,
    deadline: Instant,
) -> std::result::Result<Interface, String> {
    let pid = u64::from(child.id());
    let mut uncertain = false;
    let result = (|| {
        let mut phase = 0;
        let mut interface = None;
        loop {
            if child
                .try_wait()
                .map_err(|_| "cannot inspect launched daemon")?
                .is_some()
            {
                return Err("daemon exited before startup completed");
            }
            if Instant::now() >= deadline {
                uncertain = true;
                return Err("startup deadline expired");
            }
            let ready = server
                .wait(SysHandle::NONE, &[alarm.0])
                .map_err(|handles| {
                    if handles.contains(&alarm.0) || Instant::now() >= deadline {
                        uncertain = true;
                        "startup deadline expired"
                    } else {
                        uncertain = phase == 2;
                        "startup connection closed"
                    }
                })?;
            for handle in ready {
                if handle == alarm.0 {
                    uncertain = true;
                    return Err("startup deadline expired");
                }
                let Some(connection) = server.get_connection(handle) else {
                    continue;
                };
                if !connection.connected() {
                    continue;
                }
                // This server admits one connection. After HELLO, that
                // connection's authenticated PID and capabilities cannot change.
                if phase == 0 && ipc::authenticate(handle, Some(pid))? != DAEMON_CAPS {
                    return Err("daemon received unexpected capabilities");
                }
                if !connection.have_req() {
                    continue;
                }
                let (command, payload) = ipc::request(connection)?;
                match (phase, command) {
                    (0, HELLO) if payload.is_empty() => phase = 1,
                    (1, READY) => {
                        interface = Some(Interface::decode(&payload)?);
                        phase = 2;
                    }
                    (1, START_ERROR) if payload.len() == 2 => {
                        // The failure is definite even if its receipt is lost.
                        let _ = ipc::respond(connection, rt::E_OK, &[]);
                        return Err(match u16::from_le_bytes(payload.try_into().unwrap()) {
                            1 => "daemon rejected the configuration or its permissions",
                            _ => {
                                "daemon could not activate its transports, control service or interface"
                            }
                        });
                    }
                    (2, COMMITTED) if payload.is_empty() => {
                        ipc::respond(connection, rt::E_OK, &[])
                            .inspect_err(|_| uncertain = true)?;
                        let mut interface = interface.take().unwrap();
                        interface.state = State::Up;
                        return Ok(interface);
                    }
                    _ => return Err("invalid startup exchange"),
                }
                ipc::respond(connection, rt::E_OK, &[]).inspect_err(|_| uncertain = phase == 2)?;
            }
        }
    })();
    result.map_err(|mut error| {
        // A deadline or lost connection can race with an observable child exit.
        if uncertain && matches!(child.try_wait(), Ok(Some(_))) {
            uncertain = false;
            error = "daemon exited before startup completed";
        }
        let mut message = format!("{error} (pid={pid})");
        if uncertain {
            message.push_str("; activation is not confirmed; use wg-tool status");
        }
        message
    })
}
