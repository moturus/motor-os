use moto_sys::kernel_log::{
    KERNEL_LOG_RING_SIZE, KernelLogControl, KernelLogSnapshot, decode_kernel_log_frame,
    kernel_log_sequence_gap, snapshot_kernel_log_ring,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DrainStatus {
    Busy,
    Stable,
}

pub(crate) struct KernelLogDrain {
    previous_end: u64,
    next_sequence: u32,
    console_drops: u64,
    staging: Vec<u8>,
}

impl KernelLogDrain {
    pub(crate) fn new() -> Self {
        Self {
            previous_end: 0,
            next_sequence: 0,
            console_drops: 0,
            staging: vec![0; KERNEL_LOG_RING_SIZE],
        }
    }

    pub(crate) fn drain<F>(
        &mut self,
        ring: &[u8],
        control: &KernelLogControl,
        mut offer: F,
    ) -> DrainStatus
    where
        F: FnMut(Vec<u8>, bool) -> bool,
    {
        let snapshot = snapshot_kernel_log_ring(
            control,
            self.previous_end,
            &mut self.staging,
            |offset, dst| dst.copy_from_slice(&ring[offset..offset + dst.len()]),
        )
        .expect("the kernel-log staging buffer is ring-sized");

        let KernelLogSnapshot::Stable { end, len, lapped } = snapshot else {
            return DrainStatus::Busy;
        };
        self.previous_end = end;
        if lapped {
            return DrainStatus::Stable;
        }

        let mut frames = Vec::new();
        let mut position = 0;
        while position < len {
            let frame = match decode_kernel_log_frame(&self.staging[position..len]) {
                Ok(frame) => frame,
                Err(_) => {
                    let _ = offer(
                        b"[kernel log: corrupt framed ring snapshot]\n".to_vec(),
                        true,
                    );
                    return DrainStatus::Stable;
                }
            };
            frames.push((frame.sequence, frame.payload.to_vec()));
            position += frame.encoded_len;
        }

        for (sequence, payload) in frames {
            let lost = kernel_log_sequence_gap(self.next_sequence, sequence);
            self.next_sequence = sequence.wrapping_add(1);
            if lost != 0 {
                let marker =
                    format!("[kernel log: {lost} records lost: ring overwrite]\n").into_bytes();
                let _ = offer(marker, true);
            }
            self.offer_record(payload, false, &mut offer);
        }
        DrainStatus::Stable
    }

    fn offer_record<F>(&mut self, payload: Vec<u8>, synthetic_warning: bool, offer: &mut F)
    where
        F: FnMut(Vec<u8>, bool) -> bool,
    {
        if self.console_drops != 0 {
            let count = self.console_drops;
            let marker =
                format!("[kernel log: {count} records dropped: console backlog]\n").into_bytes();
            if !offer(marker, true) {
                self.console_drops = count.saturating_add(1);
            } else {
                self.console_drops = 0;
            }
        }

        if !offer(payload, synthetic_warning) {
            self.console_drops = self.console_drops.saturating_add(1);
        }
    }
}

pub(crate) fn run_self_tests() {
    use moto_sys::kernel_log::encode_kernel_log_frame;
    use std::sync::atomic::Ordering;

    let mut encoded = [0; 64];
    let first_len = encode_kernel_log_frame(&mut encoded, 0, b"first").unwrap();
    let second_len = encode_kernel_log_frame(&mut encoded[first_len..], 2, b"third").unwrap();

    let mut ring = vec![0; KERNEL_LOG_RING_SIZE];
    ring[..first_len + second_len].copy_from_slice(&encoded[..first_len + second_len]);
    let control = KernelLogControl::new();
    control
        .end
        .store((first_len + second_len) as u64, Ordering::Relaxed);
    control.generation.store(2, Ordering::Release);

    let mut output = Vec::new();
    let mut drain = KernelLogDrain::new();
    assert_eq!(
        drain.drain(&ring, &control, |record, warning| {
            output.push((record, warning));
            true
        }),
        DrainStatus::Stable
    );
    assert_eq!(
        output,
        [
            (b"first".to_vec(), false),
            (
                b"[kernel log: 1 records lost: ring overwrite]\n".to_vec(),
                true
            ),
            (b"third".to_vec(), false),
        ]
    );

    control.generation.store(3, Ordering::Release);
    assert_eq!(drain.drain(&ring, &control, |_, _| true), DrainStatus::Busy);

    println!("sys-tty kernel-log self-test PASS");
}
