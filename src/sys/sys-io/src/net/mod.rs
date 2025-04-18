use moto_ipc::io_channel;

mod config;
mod netdev;
mod netsys;
mod smoltcp_helpers;
mod socket;
mod tcp_listener;

pub fn init() -> Box<dyn crate::runtime::IoSubsystem> {
    let config = match config::load() {
        Ok(cfg) => cfg,
        Err(err) => panic!("Couldn't load sys-net.toml: {:?}", err),
    };

    #[cfg(debug_assertions)]
    log::debug!("{}:{} net config: {:#?}", file!(), line!(), config);

    netsys::NetSys::new(config)
}

struct TcpRxBuf {
    pub page: io_channel::IoPage,
    pub consumed: usize,
}

impl TcpRxBuf {
    fn new(page: io_channel::IoPage) -> Self {
        Self { page, consumed: 0 }
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= io_channel::PAGE_SIZE);
    }

    fn bytes_mut(&self) -> &mut [u8] {
        &mut self.page.bytes_mut()[self.consumed..]
    }
}

struct TcpTxBuf {
    page: io_channel::IoPage,
    len: usize,
    consumed: usize,
}

impl TcpTxBuf {
    fn bytes(&self) -> &[u8] {
        &self.page.bytes()[self.consumed..self.len]
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= self.len);
    }

    fn is_consumed(&self) -> bool {
        self.consumed == self.len
    }
}
