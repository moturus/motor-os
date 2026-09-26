//! Futex stress for stress-soak.sh, not part of the suite:
//! `systest futex-stress [seconds] [phase]` runs rounds of the phases below
//! (or of the one named) until the time is up. Each phase checks an exact
//! result; a lost wakeup stalls it instead, and the watchdog then prints
//! every raw-futex waiter and exits 3.
use moto_rt::futex::{futex_wait, futex_wake, futex_wake_all};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

const STALL: Duration = Duration::from_secs(30);
const MAX_SLOTS: usize = 128;
// More words than the VDSO's futex buckets, so words share buckets.
const NUM_WORDS: usize = 97;

static PROGRESS: AtomicU64 = AtomicU64::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static WORDS: [AtomicU32; NUM_WORDS] = [const { AtomicU32::new(0) }; NUM_WORDS];
// Per worker: 1 + the index of the word it waits on (0 when not waiting), and
// the value it expects there.
static WAITING_ON: [AtomicUsize; MAX_SLOTS] = [const { AtomicUsize::new(0) }; MAX_SLOTS];
static EXPECTED: [AtomicU32; MAX_SLOTS] = [const { AtomicU32::new(0) }; MAX_SLOTS];
static EARLY_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static MAX_EARLY_NS: AtomicU64 = AtomicU64::new(0);

const PHASES: [&str; 8] = [
    "mutex", "condvar", "pingpong", "timeouts", "wake-all", "park", "rwlock", "barrier",
];

fn progress() {
    PROGRESS.fetch_add(1, Ordering::Relaxed);
}

struct Rng(u64);

impl Rng {
    fn new(seed: usize) -> Self {
        Self(
            moto_rt::time::Instant::now().as_u64()
                ^ (seed as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15),
        )
    }

    fn next(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound
    }
}

// A raw futex wait that the watchdog can see.
fn wait_word(slot: usize, word: usize, expected: u32, timeout: Option<Duration>) -> bool {
    EXPECTED[slot].store(expected, Ordering::Relaxed);
    WAITING_ON[slot].store(word + 1, Ordering::Release);
    let woken = futex_wait(&WORDS[word], expected, timeout);
    WAITING_ON[slot].store(0, Ordering::Release);
    progress();
    woken
}

fn spawn_all<F>(count: usize, f: F)
where
    F: Fn(usize) + Send + Sync + 'static,
{
    let f = Arc::new(f);
    let threads: Vec<_> = (0..count)
        .map(|idx| {
            let f = f.clone();
            std::thread::spawn(move || f(idx))
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
}

fn reset_words() {
    for word in &WORDS {
        word.store(0, Ordering::Relaxed);
    }
}

fn mutex_phase(threads: usize) {
    const ITERS: u64 = 200_000;
    let counter = Arc::new(Mutex::new(0_u64));
    let shared = counter.clone();
    spawn_all(threads, move |_| {
        for _ in 0..ITERS {
            *shared.lock().unwrap() += 1;
            progress();
        }
    });
    assert_eq!(*counter.lock().unwrap(), threads as u64 * ITERS);
}

struct Queue {
    items: Mutex<(VecDeque<u64>, bool)>,
    not_empty: Condvar,
    not_full: Condvar,
}

fn condvar_phase(threads: usize) {
    const ITEMS: u64 = 200_000;
    const CAPACITY: usize = 8;
    let producers = (threads / 2).max(1) as u64;
    let queue = Arc::new(Queue {
        items: Mutex::new((VecDeque::new(), false)),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
    });
    let consumed = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));

    let producer_queue = queue.clone();
    let producer = std::thread::spawn(move || {
        let shared = producer_queue.clone();
        spawn_all(producers as usize, move |idx| {
            let producer_queue = &shared;
            let mut rng = Rng::new(idx);
            let mut value = idx as u64;
            while value < ITEMS {
                let mut items = producer_queue.items.lock().unwrap();
                while items.0.len() == CAPACITY {
                    items = if rng.next(4) == 0 {
                        let timeout = Duration::from_micros(rng.next(1000));
                        producer_queue
                            .not_full
                            .wait_timeout(items, timeout)
                            .unwrap()
                            .0
                    } else {
                        producer_queue.not_full.wait(items).unwrap()
                    };
                }
                items.0.push_back(value);
                drop(items);
                if rng.next(16) == 0 {
                    producer_queue.not_empty.notify_all();
                } else {
                    producer_queue.not_empty.notify_one();
                }
                value += producers;
                progress();
            }
        });
        producer_queue.items.lock().unwrap().1 = true;
        producer_queue.not_empty.notify_all();
    });

    let consumer_queue = queue.clone();
    let totals = consumed.clone();
    spawn_all((threads / 2).max(1), move |idx| {
        let mut rng = Rng::new(idx + 1000);
        loop {
            let mut items = consumer_queue.items.lock().unwrap();
            let item = loop {
                if let Some(item) = items.0.pop_front() {
                    break Some(item);
                }
                if items.1 {
                    break None;
                }
                items = if rng.next(4) == 0 {
                    let timeout = Duration::from_micros(rng.next(1000));
                    consumer_queue
                        .not_empty
                        .wait_timeout(items, timeout)
                        .unwrap()
                        .0
                } else {
                    consumer_queue.not_empty.wait(items).unwrap()
                };
            };
            drop(items);
            let Some(item) = item else {
                break;
            };
            consumer_queue.not_full.notify_one();
            totals.0.fetch_add(1, Ordering::Relaxed);
            totals.1.fetch_add(item, Ordering::Relaxed);
            progress();
        }
    });
    producer.join().unwrap();

    assert_eq!(consumed.0.load(Ordering::Relaxed), ITEMS);
    assert_eq!(consumed.1.load(Ordering::Relaxed), ITEMS * (ITEMS - 1) / 2);
}

// Pairs hand a raw futex word back and forth: one lost wakeup deadlocks a pair.
fn pingpong_phase(threads: usize) {
    const ROUNDS: u32 = 50_000;
    reset_words();
    let pairs = (threads / 2).clamp(1, NUM_WORDS);
    spawn_all(pairs * 2, move |slot| {
        let (word, parity) = (slot / 2, (slot % 2) as u32);
        let mut rng = Rng::new(slot);
        loop {
            let value = WORDS[word].load(Ordering::Acquire);
            if value >= 2 * ROUNDS {
                break;
            }
            if value % 2 == parity {
                WORDS[word].store(value + 1, Ordering::Release);
                futex_wake(&WORDS[word]);
                progress();
            } else {
                let timeout = (rng.next(8) == 0).then(|| Duration::from_micros(rng.next(500)));
                wait_word(slot, word, value, timeout);
            }
        }
    });
}

// Waiters with random timeouts race wakers across words that share buckets:
// timeout cleanup, wakes that race timeouts, and bucket scans by key.
fn timeouts_phase(threads: usize) {
    reset_words();
    let stop = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicUsize::new(0));
    let waiters = threads;
    let wakers = (threads / 4).max(2);

    let waiter_stop = stop.clone();
    let waiter_finished = finished.clone();
    let waiter_threads = std::thread::spawn(move || {
        spawn_all(waiters, move |slot| {
            let mut rng = Rng::new(slot);
            while !waiter_stop.load(Ordering::Acquire) {
                let word = rng.next(NUM_WORDS as u64) as usize;
                let value = WORDS[word].load(Ordering::Acquire);
                let timeout = (rng.next(4) != 0).then(|| Duration::from_micros(rng.next(3000)));
                let started = Instant::now();
                if !wait_word(slot, word, value, timeout) {
                    let timeout = timeout.expect("a wait without a timeout timed out");
                    let elapsed = started.elapsed();
                    if elapsed < timeout {
                        let early = (timeout - elapsed).as_nanos() as u64;
                        EARLY_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                        MAX_EARLY_NS.fetch_max(early, Ordering::Relaxed);
                        assert!(
                            early < 1_000_000,
                            "a futex timeout expired {early} ns early"
                        );
                    }
                }
            }
            waiter_finished.fetch_add(1, Ordering::Release);
        });
    });

    let waker_stop = stop.clone();
    spawn_all(wakers, move |idx| {
        let mut rng = Rng::new(idx + 1000);
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            let word = rng.next(NUM_WORDS as u64) as usize;
            WORDS[word].fetch_add(1, Ordering::Release);
            if rng.next(8) == 0 {
                futex_wake_all(&WORDS[word]);
            } else {
                futex_wake(&WORDS[word]);
            }
            progress();
        }
        waker_stop.store(true, Ordering::Release);
    });

    // Every waiter still blocked expects an old value: changing every word
    // and waking all its waiters must release them.
    while finished.load(Ordering::Acquire) < waiters {
        for word in &WORDS {
            word.fetch_add(1, Ordering::Release);
            futex_wake_all(word);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    waiter_threads.join().unwrap();
}

// Woken threads wait again at once while futex_wake_all may still be running.
fn wake_all_phase(threads: usize) {
    const ROUNDS: u32 = 10_000;
    reset_words();
    let arrived = Arc::new(AtomicU32::new(0));
    let waiter_arrived = arrived.clone();
    let waiters = std::thread::spawn(move || {
        spawn_all(threads, move |slot| {
            for round in 0..ROUNDS {
                while WORDS[0].load(Ordering::Acquire) == round {
                    wait_word(slot, 0, round, None);
                }
                waiter_arrived.fetch_add(1, Ordering::Release);
            }
        });
    });
    for round in 0..ROUNDS {
        WORDS[0].store(round + 1, Ordering::Release);
        futex_wake_all(&WORDS[0]);
        while arrived.load(Ordering::Acquire) < (round + 1) * threads as u32 {
            std::thread::yield_now();
        }
        progress();
    }
    waiters.join().unwrap();
}

fn park_phase(threads: usize) {
    const ROUNDS: u32 = 20_000;
    let pairs = (threads / 2).max(1);
    let joins: Vec<_> = (0..pairs)
        .map(|_| {
            let turn = Arc::new(AtomicU32::new(0));
            let peer_turn = turn.clone();
            let peer = std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    while peer_turn.load(Ordering::Acquire) != 2 * round + 1 {
                        std::thread::park();
                    }
                    peer_turn.store(2 * round + 2, Ordering::Release);
                    progress();
                }
            });
            let peer_thread = peer.thread().clone();
            let main = std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    turn.store(2 * round + 1, Ordering::Release);
                    peer_thread.unpark();
                    while turn.load(Ordering::Acquire) != 2 * round + 2 {
                        std::thread::yield_now();
                    }
                    progress();
                }
            });
            (peer, main)
        })
        .collect();
    for (peer, main) in joins {
        main.join().unwrap();
        peer.join().unwrap();
    }
}

fn rwlock_phase(threads: usize) {
    const ITERS: u64 = 100_000;
    let lock = Arc::new(RwLock::new((0_u64, 0_u64)));
    let shared = lock.clone();
    let writers = 2;
    spawn_all(threads.max(writers + 1), move |idx| {
        for _ in 0..ITERS {
            if idx < writers {
                let mut pair = shared.write().unwrap();
                pair.0 += 1;
                pair.1 += 1;
            } else {
                let pair = shared.read().unwrap();
                assert_eq!(pair.0, pair.1, "a reader saw a torn write");
            }
            progress();
        }
    });
    assert_eq!(*lock.read().unwrap(), (2 * ITERS, 2 * ITERS));
}

fn barrier_phase(threads: usize) {
    const ROUNDS: u64 = 20_000;
    let barrier = Arc::new(Barrier::new(threads));
    let leaders = Arc::new(AtomicU64::new(0));
    let shared = (barrier.clone(), leaders.clone());
    spawn_all(threads, move |_| {
        for _ in 0..ROUNDS {
            if shared.0.wait().is_leader() {
                shared.1.fetch_add(1, Ordering::Relaxed);
            }
            progress();
        }
    });
    assert_eq!(leaders.load(Ordering::Relaxed), ROUNDS);
}

fn watchdog() {
    let mut last = PROGRESS.load(Ordering::Relaxed);
    let mut since = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = PROGRESS.load(Ordering::Relaxed);
        if now != last {
            last = now;
            since = Instant::now();
            continue;
        }
        if since.elapsed() < STALL {
            continue;
        }
        let phase = PHASES[PHASE.load(Ordering::Relaxed)];
        println!("futex-stress: STALL in phase {phase}: no progress for {STALL:?}");
        for slot in 0..MAX_SLOTS {
            let word = WAITING_ON[slot].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }
            let expected = EXPECTED[slot].load(Ordering::Relaxed);
            let value = WORDS[word - 1].load(Ordering::Acquire);
            let lost = if value != expected {
                "  <-- LOST WAKE?"
            } else {
                ""
            };
            println!(
                "  worker {slot}: waits on word {} expecting {expected}, value {value}{lost}",
                word - 1
            );
        }
        std::process::exit(3);
    }
}

pub fn run(args: &[String]) {
    let seconds: u64 = args.get(2).map_or(30, |arg| arg.parse().unwrap());
    // An optional phase name runs only that phase.
    let only = args.get(3).map(|name| {
        PHASES
            .iter()
            .position(|phase| phase == name)
            .unwrap_or_else(|| panic!("unknown phase '{name}'"))
    });
    let threads = (2 * moto_sys::num_cpus() as usize).clamp(4, 32);
    std::thread::spawn(watchdog);

    let started = Instant::now();
    let mut rounds = 0;
    while started.elapsed() < Duration::from_secs(seconds) {
        for (idx, name) in PHASES.iter().enumerate() {
            if only.is_some_and(|only| only != idx) {
                continue;
            }
            PHASE.store(idx, Ordering::Relaxed);
            let phase_started = Instant::now();
            match idx {
                0 => mutex_phase(threads),
                1 => condvar_phase(threads),
                2 => pingpong_phase(threads),
                3 => timeouts_phase(threads),
                4 => wake_all_phase(threads),
                5 => park_phase(threads),
                6 => rwlock_phase(threads),
                _ => barrier_phase(threads),
            }
            println!(
                "futex-stress: round {rounds} {name} {} ms",
                phase_started.elapsed().as_millis()
            );
        }
        rounds += 1;
    }
    println!(
        "futex-stress: PASS {rounds} rounds, {} threads, {} ops, {} early timeouts (max {} ns)",
        threads,
        PROGRESS.load(Ordering::Relaxed),
        EARLY_TIMEOUTS.load(Ordering::Relaxed),
        MAX_EARLY_NS.load(Ordering::Relaxed)
    );
}
