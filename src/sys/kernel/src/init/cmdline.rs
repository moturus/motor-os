use super::{PvhMemMapEntry, PvhStartInfo};

// Includes the terminating NUL. kloader maps at most 512 GiB of physical RAM.
pub(super) const MAX_CMDLINE_BYTES: usize = moto_sys::SysRay::MAX_CMDLINE_LEN + 1;
const BOOT_DIRECT_MAP_END: u64 = 1 << 39;

pub(super) fn read(
    pvh: &PvhStartInfo,
    buf: &mut [u8; MAX_CMDLINE_BYTES],
) -> Result<usize, &'static str> {
    if pvh.cmdline_paddr == 0 {
        return Ok(0);
    }
    let len = read_limit(pvh.cmdline_paddr, pvh.mem_map())?;
    // Read before boot memory can be reused. Only the validated RAM span is
    // exposed, through kloader's direct map, never through an arbitrary VA.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (crate::mm::PAGING_DIRECT_MAP_OFFSET + pvh.cmdline_paddr) as *const u8,
            len,
        )
    };
    let bytes = terminated_bytes(bytes)?;
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

fn read_limit(paddr: u64, mem_map: &[PvhMemMapEntry]) -> Result<usize, &'static str> {
    if paddr == 0 || paddr >= BOOT_DIRECT_MAP_END {
        return Err("command line is outside the boot direct map");
    }
    let mut end = None;
    for entry in mem_map {
        let entry_end = entry
            .addr
            .checked_add(entry.size)
            .ok_or("invalid boot RAM range")?;
        if entry.available() && entry.addr <= paddr && paddr < entry_end {
            end = Some(entry_end.min(BOOT_DIRECT_MAP_END));
            break;
        }
    }
    let mut end = end.ok_or("command line is outside boot RAM")?;
    // A reserved overlap takes precedence over an available-memory entry.
    for entry in mem_map.iter().filter(|entry| !entry.available()) {
        let entry_end = entry
            .addr
            .checked_add(entry.size)
            .ok_or("invalid boot RAM range")?;
        if entry.addr <= paddr && paddr < entry_end {
            return Err("command line is in reserved memory");
        }
        if entry.size != 0 && paddr < entry.addr {
            end = end.min(entry.addr);
        }
    }
    Ok((end - paddr).min(MAX_CMDLINE_BYTES as u64) as usize)
}

fn terminated_bytes(bytes: &[u8]) -> Result<&[u8], &'static str> {
    let len = bytes
        .iter()
        .take(MAX_CMDLINE_BYTES)
        .position(|byte| *byte == 0)
        .ok_or("unterminated kernel command line")?;
    Ok(&bytes[..len])
}

#[cfg(debug_assertions)]
pub(super) fn self_test() {
    for (input, expected) in [
        (&b"\0"[..], &b""[..]),
        (b" \t\r\n\0", b" \t\r\n"),
        (b"system-tty system-tty\0", b"system-tty system-tty"),
        (b"\xffsystem-tty\0", b"\xffsystem-tty"),
        (b"ignored\0system-tty\0", b"ignored"),
    ] {
        assert_eq!(terminated_bytes(input), Ok(expected));
    }
    assert!(terminated_bytes(b"").is_err());
    assert!(terminated_bytes(b"system-tty").is_err());
    let mut bytes = [b' '; MAX_CMDLINE_BYTES + 1];
    bytes[..10].copy_from_slice(b"system-tty");
    bytes[MAX_CMDLINE_BYTES] = 0;
    assert!(terminated_bytes(&bytes).is_err());
    bytes[MAX_CMDLINE_BYTES - 1] = 0;
    assert_eq!(
        terminated_bytes(&bytes),
        Ok(&bytes[..MAX_CMDLINE_BYTES - 1])
    );

    let ram = |addr, size, entry_type| PvhMemMapEntry {
        addr,
        size,
        entry_type,
        reserved: 0,
    };
    let map = [ram(0x1000, 0x2000, 1), ram(0x4000, 0x1000, 2)];
    assert_eq!(read_limit(0x1000, &map), Ok(MAX_CMDLINE_BYTES));
    assert_eq!(read_limit(0x2fff, &map), Ok(1));
    for addr in [0, 0xfff, 0x3000, 0x4000, BOOT_DIRECT_MAP_END, u64::MAX] {
        assert!(read_limit(addr, &map).is_err());
    }
    assert!(read_limit(1, &[]).is_err());
    assert!(read_limit(1, &[ram(1, u64::MAX, 1)]).is_err());
    let overlap = [ram(0x1000, 0x3000, 1), ram(0x2000, 0x1000, 2)];
    assert_eq!(read_limit(0x1fff, &overlap), Ok(1));
    assert!(read_limit(0x2000, &overlap).is_err());
    assert_eq!(
        read_limit(BOOT_DIRECT_MAP_END - 1, &[ram(0, u64::MAX, 1)]),
        Ok(1)
    );
    let pvh = PvhStartInfo {
        magic: [0; 4],
        version: 0,
        flags: 0,
        nr_modules: 0,
        modlist_paddr: 0,
        cmdline_paddr: 0,
        rsdp_paddr: 0,
        memmap_paddr: 0,
        memmap_entries: 0,
        _pad: 0,
    };
    // The absent command line must not even consult the memory-map pointer.
    let mut buf = [0xaa; MAX_CMDLINE_BYTES];
    assert_eq!(read(&pvh, &mut buf), Ok(0));
    assert_eq!(buf, [0xaa; MAX_CMDLINE_BYTES]);
    crate::raw_log!("kernel command-line tests PASS");
}
