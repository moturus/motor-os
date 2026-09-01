use moto_sys::kernel_log::{
    DecodedKernelLogFrame, KERNEL_LOG_FRAME_MAGIC_V1, KERNEL_LOG_MAX_PAYLOAD, KERNEL_LOG_RING_SIZE,
    KernelLogControl, KernelLogFrameError, KernelLogSnapshot, decode_kernel_log_frame,
    encode_kernel_log_frame, kernel_log_control_is_aligned, kernel_log_sequence_gap,
    snapshot_kernel_log_ring,
};
use std::fs::File;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const KERNEL_LOG_PATH: &str = "/system/logs/kernel.log";
const KERNEL_LOG_PREVIOUS_PATH: &str = "/system/logs/kernel.log.prev";
const LOG_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const BOOT_PREAMBLE_PREFIX: &[u8] = b"[kernel log: file forwarding started at ";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn wait_for_file_records(records: &[&[u8]]) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut log = std::fs::read(KERNEL_LOG_PREVIOUS_PATH).unwrap_or_default();
        log.extend(std::fs::read(KERNEL_LOG_PATH).unwrap_or_default());
        if records.iter().all(|record| contains(&log, record)) {
            return log;
        }
        if Instant::now() >= deadline {
            let missing = records
                .iter()
                .find(|record| !contains(&log, record))
                .unwrap();
            panic!("kernel log files missing test record {missing:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn boot_milestone(log: &[u8]) -> u128 {
    const SUFFIX: &[u8] = b"ms since boot]\n";
    let start = log
        .windows(BOOT_PREAMBLE_PREFIX.len())
        .position(|window| window == BOOT_PREAMBLE_PREFIX)
        .expect("kernel log boot preamble")
        + BOOT_PREAMBLE_PREFIX.len();
    let end = log[start..]
        .windows(SUFFIX.len())
        .position(|window| window == SUFFIX)
        .expect("kernel log boot preamble suffix")
        + start;
    std::str::from_utf8(&log[start..end])
        .unwrap()
        .parse()
        .unwrap()
}

fn file_mode_end_to_end() {
    if crate::skip_without_cap_log("kernel_log::file_mode_end_to_end") {
        return;
    }

    // The preamble is written once at boot; a debug build's DEBUG-record
    // volume rotates it out of both log files before systest runs.
    if !cfg!(debug_assertions) {
        let initial = wait_for_file_records(&[BOOT_PREAMBLE_PREFIX]);
        let milestone = boot_milestone(&initial);
        assert!(milestone <= 1_000, "boot milestone {milestone}ms");
    }

    let nonce = format!("kernel-e2e-{:016x}", std::random::random::<u64>(..));
    let records = [
        format!("  0:001: ERROR file.rs:1: {nonce} error\n"),
        format!("  0:002: WARN file.rs:2: {nonce} unsafe \x1b[31m \u{009b}32m\n"),
        format!("  0:003: INFO file.rs:3: {nonce} info\n"),
        format!("  0:004: DEBUG file.rs:4: {nonce} debug\n"),
        format!("{nonce} free text\n"),
        format!("{nonce} newline-free"),
        format!("{nonce} multi-line first\n{nonce} multi-line second\n"),
    ];
    for record in &records {
        moto_sys::SysRay::log(record).unwrap();
    }
    let expected: Vec<&[u8]> = records.iter().map(|record| record.as_bytes()).collect();
    wait_for_file_records(&expected);

    // Quiescence is also release-only: in debug, any background process's
    // file operation lands more DEBUG records in kernel.log.
    if !cfg!(debug_assertions) {
        let file = File::open(KERNEL_LOG_PATH).unwrap();
        std::thread::sleep(Duration::from_secs(1));
        let before = file.metadata().unwrap().len();
        std::thread::sleep(Duration::from_secs(5));
        let after = file.metadata().unwrap().len();
        assert_eq!(before, after, "kernel.log did not become quiescent");
    }

    let flood_prefix = format!("kernel-rotation-{nonce} ");
    let flood = format!("{flood_prefix}{}\n", "x".repeat(220 - flood_prefix.len()));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        for _ in 0..32 {
            moto_sys::SysRay::log(&flood).unwrap();
        }
        std::thread::sleep(Duration::from_millis(10));
        let previous = std::fs::read(KERNEL_LOG_PREVIOUS_PATH).unwrap_or_default();
        if contains(&previous, flood_prefix.as_bytes()) {
            break;
        }
        assert!(Instant::now() < deadline, "kernel.log did not rotate");
    }

    let marker = format!("{nonce} after rotation\n");
    moto_sys::SysRay::log(&marker).unwrap();
    wait_for_file_records(&[marker.as_bytes()]);
    assert!(std::fs::metadata(KERNEL_LOG_PREVIOUS_PATH).unwrap().len() <= LOG_FILE_MAX_BYTES);
    assert!(std::fs::metadata(KERNEL_LOG_PATH).unwrap().len() <= LOG_FILE_MAX_BYTES);
    println!("kernel_log::file_mode_end_to_end PASS");
}

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

    file_mode_end_to_end();

    println!("kernel_log::run_all_tests PASS");
}
