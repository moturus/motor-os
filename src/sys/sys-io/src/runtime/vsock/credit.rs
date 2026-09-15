#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CreditAdvertisement {
    pub(crate) buf_alloc: u32,
    pub(crate) fwd_cnt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreditError {
    CapacityTooLarge,
    ReceiveCapacityExceeded,
    ForwardedBeyondBuffered,
    PeerForwardedBeyondSent,
    TxExceedsPeerCredit,
}

pub(crate) struct CreditState {
    rx_capacity: usize,
    rx_buffered: usize,
    fwd_cnt: u32,
    tx_cnt: u32,
    peer: CreditAdvertisement,
}

impl CreditState {
    pub(crate) fn new(rx_capacity: usize) -> Result<Self, CreditError> {
        u32::try_from(rx_capacity).map_err(|_| CreditError::CapacityTooLarge)?;
        Ok(Self {
            rx_capacity,
            rx_buffered: 0,
            fwd_cnt: 0,
            tx_cnt: 0,
            peer: CreditAdvertisement {
                buf_alloc: 0,
                fwd_cnt: 0,
            },
        })
    }

    pub(crate) fn local_advertisement(&self) -> CreditAdvertisement {
        CreditAdvertisement {
            buf_alloc: self.rx_capacity as u32,
            fwd_cnt: self.fwd_cnt,
        }
    }

    pub(crate) fn rx_allowance(&self) -> usize {
        self.rx_capacity - self.rx_buffered
    }

    pub(crate) fn record_received(&mut self, len: usize) -> Result<(), CreditError> {
        let buffered = self
            .rx_buffered
            .checked_add(len)
            .filter(|buffered| *buffered <= self.rx_capacity)
            .ok_or(CreditError::ReceiveCapacityExceeded)?;
        self.rx_buffered = buffered;
        Ok(())
    }

    /// Record bytes removed from the receive buffer and copied into already
    /// reserved IPC storage. Client reads and page release do not call this.
    pub(crate) fn record_forwarded_to_ipc(&mut self, len: usize) -> Result<(), CreditError> {
        let buffered = self
            .rx_buffered
            .checked_sub(len)
            .ok_or(CreditError::ForwardedBeyondBuffered)?;
        let len = u32::try_from(len).map_err(|_| CreditError::ForwardedBeyondBuffered)?;
        self.rx_buffered = buffered;
        self.fwd_cnt = self.fwd_cnt.wrapping_add(len);
        Ok(())
    }

    pub(crate) fn update_peer(&mut self, peer: CreditAdvertisement) -> Result<(), CreditError> {
        let outstanding = self.tx_cnt.wrapping_sub(self.peer.fwd_cnt);
        let advanced = peer.fwd_cnt.wrapping_sub(self.peer.fwd_cnt);
        if advanced > outstanding {
            return Err(CreditError::PeerForwardedBeyondSent);
        }
        self.peer = peer;
        Ok(())
    }

    pub(crate) fn tx_allowance(&self) -> u32 {
        let outstanding = self.tx_cnt.wrapping_sub(self.peer.fwd_cnt);
        // A peer may shrink its allocation below bytes already outstanding.
        // That advertises no new allowance; it must not wrap into a huge one.
        self.peer.buf_alloc.saturating_sub(outstanding)
    }

    /// Record payload bytes only after the single TX pump has synchronously
    /// published them. The pump prechecks this same allowance without yielding.
    pub(crate) fn charge_tx_after_publish(&mut self, len: u32) -> Result<(), CreditError> {
        if len > self.tx_allowance() {
            return Err(CreditError::TxExceedsPeerCredit);
        }
        self.tx_cnt = self.tx_cnt.wrapping_add(len);
        Ok(())
    }
}
