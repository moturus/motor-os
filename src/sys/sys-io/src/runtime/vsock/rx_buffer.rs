use std::{collections::VecDeque, io::ErrorKind};

use super::credit::{CreditAdvertisement, CreditError, CreditState};

pub(crate) struct StreamBuffer {
    bytes: VecDeque<u8>,
    credit: CreditState,
}

impl StreamBuffer {
    pub(crate) fn new(rx_capacity: usize) -> std::io::Result<Self> {
        // Validate the protocol-visible capacity before attempting allocation.
        let credit = CreditState::new(rx_capacity).map_err(|_| ErrorKind::InvalidInput)?;
        let mut bytes = VecDeque::new();
        bytes
            .try_reserve_exact(rx_capacity)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        Ok(Self { bytes, credit })
    }

    pub(crate) fn credit(&self) -> &CreditState {
        &self.credit
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
    }

    pub(crate) fn update_peer(&mut self, peer: CreditAdvertisement) -> Result<(), CreditError> {
        self.credit.update_peer(peer)
    }

    pub(crate) fn charge_tx_after_publish(&mut self, len: u32) -> Result<(), CreditError> {
        self.credit.charge_tx_after_publish(len)
    }

    /// Append one accepted packet or reject it without retaining a prefix.
    pub(crate) fn try_append_packet(&mut self, payload: &[u8]) -> Result<(), CreditError> {
        self.credit.record_received(payload.len())?;
        debug_assert!(self.bytes.capacity() - self.bytes.len() >= payload.len());
        self.bytes.extend(payload.iter().copied());
        Ok(())
    }

    /// Copy an ordered prefix into storage the caller has already reserved.
    /// Client reads and later release of that storage do not affect credit.
    pub(crate) fn copy_into_reserved(&mut self, dst: &mut [u8]) -> usize {
        let len = dst.len().min(self.bytes.len());
        if len == 0 {
            return 0;
        }

        let (first, second) = self.bytes.as_slices();
        let first_len = first.len().min(len);
        dst[..first_len].copy_from_slice(&first[..first_len]);
        let second_len = len - first_len;
        dst[first_len..len].copy_from_slice(&second[..second_len]);

        self.credit
            .record_forwarded_to_ipc(len)
            .expect("stream bytes and receive credit diverged");
        drop(self.bytes.drain(..len));
        len
    }
}
