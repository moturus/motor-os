//! Physical placement and churn over the kernel's block allocator: fresh
//! eager allocations pack into few 2 MiB blocks, and mixed-size churn across
//! threads never aliases live pages.

use moto_sys::SysMem;
use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use std::collections::VecDeque;
use std::sync::mpsc;

const BLOCK_SHIFT: u64 = 21;

struct Mapping {
    addr: u64,
    pages: u64,
}

impl Mapping {
    fn alloc(pages: u64) -> Self {
        let addr = SysMem::alloc(PAGE_SIZE_SMALL, pages).unwrap();
        Self { addr, pages }
    }

    // Two words per page carry a mapping-specific pattern; a page shared
    // between two live mappings would fail the other one's readback.
    fn fill(&self, seed: u64) {
        for page in 0..self.pages {
            let base = (self.addr + page * PAGE_SIZE_SMALL) as *mut u64;
            unsafe {
                base.write_volatile(seed ^ page);
                base.add(511).write_volatile(!(seed ^ page));
            }
        }
    }

    fn verify(&self, seed: u64) {
        for page in 0..self.pages {
            let base = (self.addr + page * PAGE_SIZE_SMALL) as *const u64;
            let (first, last) = unsafe { (base.read_volatile(), base.add(511).read_volatile()) };
            assert_eq!((first, last), (seed ^ page, !(seed ^ page)));
        }
    }

    fn blocks(&self, out: &mut Vec<u64>) {
        for page in 0..self.pages {
            let phys = SysMem::virt_to_phys(self.addr + page * PAGE_SIZE_SMALL).unwrap();
            out.push(phys >> BLOCK_SHIFT);
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        SysMem::free(self.addr).unwrap();
    }
}

// Eight 1 MiB pieces: ideal packing needs four blocks. The allocator drains
// every split block that boot left partially free before splitting a whole
// one: the page-zero block, the kloader page-table block, up to two initrd
// boundary blocks and the list-state table block, at most six. Each CPU adds
// the block its cursor was filling plus one more when a piece straddles two
// fresh blocks. The budget is asserted only on a fresh boot (the focused
// subcommand); the full suite reports placement.
const IDEAL_BLOCKS: usize = 4;
const BOOT_SPLIT_BLOCKS: usize = 6;

fn placement(assert_budget: bool) {
    let mut blocks = Vec::with_capacity(8 * 256);
    let pieces: [Mapping; 8] = core::array::from_fn(|_| Mapping::alloc(256));
    for (idx, piece) in pieces.iter().enumerate() {
        piece.fill(0x5eed_0000 + idx as u64);
    }
    for (idx, piece) in pieces.iter().enumerate() {
        piece.verify(0x5eed_0000 + idx as u64);
        piece.blocks(&mut blocks);
    }
    blocks.sort_unstable();
    blocks.dedup();
    let budget = IDEAL_BLOCKS + BOOT_SPLIT_BLOCKS + 2 * moto_sys::num_cpus() as usize;
    println!(
        "mem_blocks: 8 MiB of fresh pages in {} distinct 2 MiB blocks (budget {budget})",
        blocks.len()
    );
    if assert_budget {
        assert!(
            blocks.len() <= budget,
            "placement spread over {} blocks, budget {budget}",
            blocks.len()
        );
    }
}

struct Prng(u64);

impl Prng {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound
    }
}

// Four threads in a ring: each retains its newest allocations, verifies the
// oldest before releasing it, and hands every other release to its neighbor
// so frees cross CPUs and cursors.
fn churn() {
    const THREADS: usize = 4;
    const ITERATIONS: u32 = 512;
    let mut senders = Vec::new();
    let mut receivers = VecDeque::new();
    for _ in 0..THREADS {
        let (tx, rx) = mpsc::channel::<(Mapping, u64)>();
        senders.push(tx);
        receivers.push_back(rx);
    }
    let handles: Vec<_> = (0..THREADS)
        .map(|thread| {
            let rx = receivers.pop_front().unwrap();
            let tx = senders[(thread + 1) % THREADS].clone();
            std::thread::spawn(move || {
                let mut prng = Prng(0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(thread as u64 + 1));
                let mut retained = VecDeque::new();
                for iteration in 0..ITERATIONS {
                    let pages = 1 + prng.next(256);
                    let seed = (thread as u64) << 32 | u64::from(iteration);
                    let mapping = Mapping::alloc(pages);
                    mapping.fill(seed);
                    retained.push_back((mapping, seed));
                    if retained.len() > 8 {
                        let (old, seed) = retained.pop_front().unwrap();
                        old.verify(seed);
                        if iteration % 2 == 1 {
                            tx.send((old, seed)).unwrap();
                        }
                    }
                    while let Ok((mapping, seed)) = rx.try_recv() {
                        mapping.verify(seed);
                    }
                }
                drop(tx);
                for (mapping, seed) in retained {
                    mapping.verify(seed);
                }
                for (mapping, seed) in rx {
                    mapping.verify(seed);
                }
            })
        })
        .collect();
    drop(senders);
    for handle in handles {
        handle.join().unwrap();
    }
    println!("mem_blocks: churn PASS");
}

pub fn placement_subcommand() {
    placement(true);
    println!("mem_blocks: placement PASS");
}

pub fn run_all_tests() {
    placement(false);
    churn();
}
