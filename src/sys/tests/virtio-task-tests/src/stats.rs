use std::cell::Cell;

#[derive(Default)]
pub struct FsStats {
    pub device_reads: Cell<u64>,
    pub device_read_blocks: Cell<u64>,
    pub device_read_ticks: Cell<u64>,
    pub device_writes: Cell<u64>,
    pub device_write_blocks: Cell<u64>,
}

pub const TIMINGS: bool = false;
pub fn now_ticks() -> u64 {
    0
}
