use super::virtio_device::VirtioDevice;
use crate::spin::Mutex;

static RNG: Mutex<Option<Rng>> = Mutex::new(None);

pub(super) struct Rng {
    dev: alloc::boxed::Box<VirtioDevice>,
}

impl Rng {
    fn self_init(&mut self) -> Result<(), ()> {
        self.dev.acknowledge_driver(); // Step 3
        self.negotiate_features()?; // Steps 4, 5, and 6
        self.dev.init_virtqueues(1, 1)?; // Step 7
        self.dev.driver_ok(); // Step 8
        Ok(())
    }

    pub(super) fn init(dev: alloc::boxed::Box<VirtioDevice>) {
        let mut guard = RNG.lock();
        if !guard.is_none() {
            log::info!(
                "Skipping Virtio RNG device {:?} because already have one.",
                guard.as_ref().unwrap().dev.pci_device.id
            );
            dev.mark_failed();
            return;
        }
        let mut rng = Rng { dev };

        if rng.self_init().is_ok() {
            log::debug!("Initialized Virtio RNG device {:?}.", rng.dev.pci_device.id);
            *guard = Some(rng);
        } else {
            rng.dev.mark_failed();
        }
    }

    // Step 4
    fn negotiate_features(&self) -> Result<(), ()> {
        let features_available = self.dev.get_available_features();

        if (features_available & super::virtio_device::VIRTIO_F_VERSION_1) == 0 {
            log::warn!("Virtio RNG device {:?}: VIRTIO_F_VERSION_1 feature not available; features: 0x{:x}.",
                self.dev.pci_device.id, features_available);
            return Err(());
        }

        let mut unknown_features = features_available ^ super::virtio_device::VIRTIO_F_VERSION_1;
        unknown_features &= !super::virtio_device::VIRTIO_F_RING_INDIRECT_DESC;
        unknown_features &= !super::virtio_device::VIRTIO_F_RING_EVENT_IDX;

        if unknown_features != 0 {
            log::warn!(
                "Virtio RNG device {:?}: has unrecognized features: 0x{:x}.",
                self.dev.pci_device.id,
                features_available ^ super::virtio_device::VIRTIO_F_VERSION_1
            );
        }

        let features_acked = super::virtio_device::VIRTIO_F_VERSION_1;
        self.dev.write_enabled_features(features_acked);
        self.dev.confirm_features()
    }
}
