use moto_sys::kernel_log::{
    DecodedKernelLogFrame, KERNEL_LOG_FRAME_MAGIC_V1, KERNEL_LOG_MAX_PAYLOAD, KERNEL_LOG_RING_SIZE,
    KernelLogControl, KernelLogFrameError, KernelLogSnapshot, decode_kernel_log_frame,
    encode_kernel_log_frame, kernel_log_control_is_aligned, kernel_log_sequence_gap,
    snapshot_kernel_log_ring,
};
use std::sync::atomic::Ordering;

fn put_wrapped(ring: &mut [u8], start: usize, bytes: &[u8]) {
    let first = bytes.len().min(ring.len() - start);
    ring[start..start + first].copy_from_slice(&bytes[..first]);
    ring[..bytes.len() - first].copy_from_slice(&bytes[first..]);
}

fn copy_ring(ring: &[u8], offset: usize, dst: &mut [u8]) {
    dst.copy_from_slice(&ring[offset..offset + dst.len()]);
}

pub fn run_all_tests() {
    let mut encoded = vec![0; KERNEL_LOG_RING_SIZE];
    let len = encode_kernel_log_frame(&mut encoded, 0x1234_5678, b"hello").unwrap();
    assert_eq!(&encoded[..8], &[b'K', b'1', 5, 0, 0x78, 0x56, 0x34, 0x12]);
    assert_eq!(KERNEL_LOG_FRAME_MAGIC_V1.to_le_bytes(), *b"K1");
    assert_eq!(
        decode_kernel_log_frame(&encoded[..len]).unwrap(),
        DecodedKernelLogFrame {
            sequence: 0x1234_5678,
            payload: b"hello",
            encoded_len: len,
        }
    );

    let zero_len = encode_kernel_log_frame(&mut encoded, 9, b"").unwrap();
    assert_eq!(
        decode_kernel_log_frame(&encoded[..zero_len])
            .unwrap()
            .payload,
        b""
    );
    let max = vec![b'x'; KERNEL_LOG_MAX_PAYLOAD];
    assert_eq!(
        encode_kernel_log_frame(&mut encoded, 10, &max).unwrap(),
        KERNEL_LOG_RING_SIZE
    );
    assert_eq!(
        encode_kernel_log_frame(&mut encoded, 10, &[0; KERNEL_LOG_MAX_PAYLOAD + 1]),
        Err(KernelLogFrameError::PayloadTooLarge)
    );
    assert_eq!(
        encode_kernel_log_frame(&mut [0; 8], 10, b"x"),
        Err(KernelLogFrameError::BufferTooSmall)
    );
    assert_eq!(
        decode_kernel_log_frame(&encoded[..7]),
        Err(KernelLogFrameError::TruncatedHeader)
    );
    encoded[0] ^= 1;
    assert_eq!(
        decode_kernel_log_frame(&encoded[..8]),
        Err(KernelLogFrameError::BadMagic)
    );

    let control = KernelLogControl::new();
    let control_addr = &control as *const KernelLogControl as usize;
    assert!(kernel_log_control_is_aligned(control_addr));
    assert!(!kernel_log_control_is_aligned(control_addr + 1));

    let frame_len = encode_kernel_log_frame(&mut encoded, u32::MAX, b"wrapped").unwrap();
    let previous_end = KERNEL_LOG_RING_SIZE as u64 - 3;
    let mut ring = vec![0; KERNEL_LOG_RING_SIZE];
    put_wrapped(&mut ring, previous_end as usize, &encoded[..frame_len]);
    control
        .end
        .store(previous_end + frame_len as u64, Ordering::Relaxed);
    control.generation.store(2, Ordering::Release);

    let mut staging = vec![0; KERNEL_LOG_RING_SIZE];
    let snapshot = snapshot_kernel_log_ring(&control, previous_end, &mut staging, |offset, dst| {
        copy_ring(&ring, offset, dst)
    })
    .unwrap();
    assert_eq!(
        snapshot,
        KernelLogSnapshot::Stable {
            end: previous_end + frame_len as u64,
            len: frame_len,
            lapped: false,
        }
    );
    let decoded = decode_kernel_log_frame(&staging[..frame_len]).unwrap();
    assert_eq!(decoded.sequence, u32::MAX);
    assert_eq!(decoded.payload, b"wrapped");

    control.generation.store(4, Ordering::Release);
    let mut copies = 0;
    let snapshot = snapshot_kernel_log_ring(&control, previous_end, &mut staging, |offset, dst| {
        copy_ring(&ring, offset, dst);
        copies += 1;
        if copies == 1 {
            control.generation.store(5, Ordering::Release);
        }
    })
    .unwrap();
    assert_eq!(snapshot, KernelLogSnapshot::Busy);

    control.generation.store(6, Ordering::Release);
    control.end.store(
        previous_end + KERNEL_LOG_RING_SIZE as u64 + 1,
        Ordering::Relaxed,
    );
    let snapshot = snapshot_kernel_log_ring(&control, previous_end, &mut staging, |_, _| {
        panic!("a lapped snapshot must not copy ring bytes")
    })
    .unwrap();
    assert_eq!(
        snapshot,
        KernelLogSnapshot::Stable {
            end: previous_end + KERNEL_LOG_RING_SIZE as u64 + 1,
            len: 0,
            lapped: true,
        }
    );

    control.generation.store(7, Ordering::Release);
    assert_eq!(
        snapshot_kernel_log_ring(&control, previous_end, &mut staging, |_, _| {}).unwrap(),
        KernelLogSnapshot::Busy
    );
    assert_eq!(kernel_log_sequence_gap(10, 10), 0);
    assert_eq!(kernel_log_sequence_gap(10, 13), 3);
    assert_eq!(kernel_log_sequence_gap(u32::MAX, 0), 1);

    println!("kernel_log::run_all_tests PASS");
}
