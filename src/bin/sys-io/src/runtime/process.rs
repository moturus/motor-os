// Local (on-host) process.
use moto_ipc::io_channel;
use moto_sys::SysHandle;

pub struct Process {
    conn: io_channel::Server,
}

impl Process {
    pub fn from_conn(conn: io_channel::Server) -> Self {
        Self { conn }
    }

    pub fn handle(&self) -> SysHandle {
        self.conn.wait_handle()
    }

    pub fn conn(&mut self) -> &mut io_channel::Server {
        &mut self.conn
    }
}
