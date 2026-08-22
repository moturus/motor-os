//! Bounds client channels registered with the single-threaded IO runtime.

use core::ops::Deref;
use std::{cell::Cell, rc::Rc};

const KERNEL_MAX_WAIT_HANDLES: usize = 1024;
// Leaves room for IPC listeners, channels being refused, and VirtIO IRQs.
const MAX_CHANNELS: usize = KERNEL_MAX_WAIT_HANDLES - 64;
// Keep 64 slots available to the other subsystem.
const MAX_CHANNELS_PER_KIND: usize = MAX_CHANNELS - 64;

/// Runtime-owned channel counts. The two values are also exported as metrics.
#[derive(Default)]
pub(crate) struct ChannelBudget {
    net: Rc<Cell<usize>>,
    fs: Rc<Cell<usize>>,
}

impl ChannelBudget {
    pub(crate) fn admit_net(
        &self,
        sender: moto_ipc::io_channel::Sender,
    ) -> Result<ClientSender, moto_ipc::io_channel::Sender> {
        Self::admit(sender, &self.net, &self.fs)
    }

    pub(crate) fn admit_fs(
        &self,
        sender: moto_ipc::io_channel::Sender,
    ) -> Result<ClientSender, moto_ipc::io_channel::Sender> {
        Self::admit(sender, &self.fs, &self.net)
    }

    pub(crate) fn net_channels(&self) -> u64 {
        self.net.get() as u64
    }

    pub(crate) fn fs_channels(&self) -> u64 {
        self.fs.get() as u64
    }

    fn admit(
        sender: moto_ipc::io_channel::Sender,
        own: &Rc<Cell<usize>>,
        peer: &Cell<usize>,
    ) -> Result<ClientSender, moto_ipc::io_channel::Sender> {
        if !can_admit(own.get(), peer.get()) {
            return Err(sender);
        }
        own.set(own.get() + 1);
        Ok(ClientSender {
            sender,
            _slot: Rc::new(ChannelSlot(own.clone())),
        })
    }
}

fn can_admit(own: usize, peer: usize) -> bool {
    own < MAX_CHANNELS_PER_KIND && own + peer < MAX_CHANNELS
}

struct ChannelSlot(Rc<Cell<usize>>);

impl Drop for ChannelSlot {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

/// A sender whose shared slot lives until its last clone is dropped.
#[derive(Clone)]
pub(crate) struct ClientSender {
    sender: moto_ipc::io_channel::Sender,
    _slot: Rc<ChannelSlot>,
}

impl Deref for ClientSender {
    type Target = moto_ipc::io_channel::Sender;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}

#[cfg(debug_assertions)]
pub(crate) const SELF_TESTS: &[&[crate::self_test::SelfTest]] = &[self_test::TESTS];

#[cfg(debug_assertions)]
mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert};

    pub(crate) const TESTS: &[SelfTest] = &[
        ("channel_budget::per_kind_cap", per_kind_cap),
        ("channel_budget::total_cap", total_cap),
        (
            "channel_budget::reserved_peer_capacity",
            reserved_peer_capacity,
        ),
    ];

    fn per_kind_cap() -> Result<(), String> {
        st_assert!(can_admit(MAX_CHANNELS_PER_KIND - 1, 0));
        st_assert!(!can_admit(MAX_CHANNELS_PER_KIND, 0));
        Ok(())
    }

    fn total_cap() -> Result<(), String> {
        let peer = MAX_CHANNELS - MAX_CHANNELS_PER_KIND;
        st_assert!(can_admit(MAX_CHANNELS_PER_KIND - 1, peer));
        st_assert!(!can_admit(MAX_CHANNELS_PER_KIND - 1, peer + 1));
        st_assert!(MAX_CHANNELS <= KERNEL_MAX_WAIT_HANDLES);
        Ok(())
    }

    fn reserved_peer_capacity() -> Result<(), String> {
        let reserved = MAX_CHANNELS - MAX_CHANNELS_PER_KIND;
        st_assert!(can_admit(reserved - 1, MAX_CHANNELS_PER_KIND));
        st_assert!(!can_admit(reserved, MAX_CHANNELS_PER_KIND));
        Ok(())
    }
}
