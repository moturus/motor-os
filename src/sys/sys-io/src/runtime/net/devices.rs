//! Stable device indices, with removed devices retained only for their users.
use std::collections::HashMap;
use std::ops::{Index, IndexMut};

use super::device::NetDev;

#[derive(Default)]
pub(super) struct Devices {
    active: Vec<Option<NetDev<'static>>>,
    retiring: HashMap<usize, RetiringDevice>,
}

struct RetiringDevice {
    device: NetDev<'static>,
    cleanup_complete: bool,
}

impl Devices {
    pub(super) fn slot_count(&self) -> usize {
        self.active.len()
    }

    pub(super) fn push(&mut self, device: NetDev<'static>) -> usize {
        let index = self.active.len();
        self.active.push(Some(device));
        index
    }

    pub(super) fn get(&self, index: usize) -> Option<&NetDev<'static>> {
        self.active.get(index)?.as_ref()
    }

    pub(super) fn get_mut(&mut self, index: usize) -> Option<&mut NetDev<'static>> {
        self.active.get_mut(index)?.as_mut()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (usize, &NetDev<'static>)> {
        self.active
            .iter()
            .enumerate()
            .filter_map(|(index, device)| Some((index, device.as_ref()?)))
    }

    /// Withdraw from discovery before detaching users. Existing socket handles
    /// still index the retiring entry until their final cleanup releases it.
    #[cfg_attr(
        not(debug_assertions),
        expect(dead_code, reason = "removal follows in step 2")
    )]
    pub(super) fn retire(&mut self, index: usize) -> bool {
        let Some(mut device) = self.active.get_mut(index).and_then(Option::take) else {
            return false;
        };
        device.stop_polling();
        let retired = RetiringDevice {
            device,
            cleanup_complete: false,
        };
        assert!(self.retiring.insert(index, retired).is_none());
        true
    }

    /// Keep removal notifications charged to the retiring-device quota even
    /// when their clients are slow and all netstack sockets are already gone.
    #[cfg_attr(
        not(debug_assertions),
        expect(dead_code, reason = "removal follows in step 2")
    )]
    pub(super) fn finish_removal(&mut self, index: usize) {
        self.retiring.get_mut(&index).unwrap().cleanup_complete = true;
        self.reap(index);
    }

    pub(super) fn reap(&mut self, index: usize) {
        if let Some(retired) = self.retiring.get(&index) {
            retired.device.device_runtime_notify.notify_all();
        }
        if self.retiring.get(&index).is_some_and(|retired| {
            retired.cleanup_complete
                && retired.device.pending_tasks == 0
                && retired.device.sockets.iter().next().is_none()
        }) {
            self.retiring.remove(&index);
        }
    }

    pub(super) fn retained_mut(&mut self, index: usize) -> Option<&mut NetDev<'static>> {
        self.active
            .get_mut(index)
            .and_then(Option::as_mut)
            .or_else(|| {
                self.retiring
                    .get_mut(&index)
                    .map(|retired| &mut retired.device)
            })
    }
}

// Indexing is for users that already own a socket or another device resource.
// New work and enumeration must use get()/get_mut()/iter(), which exclude retirees.
impl Index<usize> for Devices {
    type Output = NetDev<'static>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .or_else(|| self.retiring.get(&index).map(|retired| &retired.device))
            .expect("device user outlived its retained state")
    }
}

impl IndexMut<usize> for Devices {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.retained_mut(index)
            .expect("device user outlived its retained state")
    }
}

#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::runtime::net::{config, device::NetstackDevice};
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};
    use futures::FutureExt;
    use std::rc::Rc;

    pub(crate) const TESTS: &[SelfTest] = &[(
        "net::devices::removed_indices_stay_vacant_and_resources_retire",
        removed_indices_stay_vacant_and_resources_retire,
    )];

    fn device(name: &str) -> NetDev<'static> {
        let config: config::NetConfig =
            toml::from_str("auto_icmp_echo_reply = false\nloopback = true\n[devices]\n").unwrap();
        NetDev::new(
            name,
            &config::DeviceCfg::new("02:00:00:00:00:01"),
            &config,
            NetstackDevice::Loopback(moto_netstack::phy::Loopback::new(
                moto_netstack::phy::Medium::Ip,
            )),
        )
    }

    fn removed_indices_stay_vacant_and_resources_retire() -> Result<(), String> {
        let mut devices = Devices::default();
        let boot = devices.push(device("loopback"));
        let other = devices.push(device("wg1"));
        for expected in 2..10 {
            let index = devices.push(device("wg0"));
            st_assert_eq!(index, expected);
            let life = Rc::downgrade(&devices[index].device_runtime_notify);
            let buffer = || moto_netstack::socket::icmp::PacketBuffer::new(vec![], vec![]);
            let handle = devices[index].sockets.add(
                1,
                moto_netstack::socket::icmp::Socket::new(buffer(), buffer()),
            );
            let polled = devices[index].poll_completion();
            st_assert!(devices.retire(index));
            st_assert!(polled.now_or_never().unwrap().is_err());
            st_assert!(!devices.retire(index));
            st_assert!(devices.active[index].is_none());
            st_assert!(devices.get(index).is_none());
            st_assert!(devices.get_mut(index).is_none());
            st_assert_eq!(
                devices.iter().map(|(idx, _)| idx).collect::<Vec<_>>(),
                vec![boot, other]
            );
            devices.reap(index);
            st_assert!(life.upgrade().is_some());
            devices[index].sockets.remove(handle);
            devices.reap(index);
            st_assert!(life.upgrade().is_some());
            devices.finish_removal(index);
            st_assert!(life.upgrade().is_none());
            st_assert!(devices.retiring.is_empty());
            st_assert_eq!(devices[boot].name(), "loopback");
            st_assert_eq!(devices[other].name(), "wg1");
        }
        st_assert!(devices.retire(other));
        devices.finish_removal(other);
        st_assert_eq!(devices.iter().count(), 1);
        st_assert_eq!(devices.slot_count(), 10);
        Ok(())
    }
}
