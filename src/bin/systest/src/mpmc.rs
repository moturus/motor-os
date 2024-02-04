use std::time::Instant;

use moto_mpmc as crossbeam_channel;

use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;

#[repr(C, align(64))]
struct Msg {
    data: [u64; 8],
}

const _: () = assert!(core::mem::size_of::<Msg>() == 64);

impl Msg {
    fn new(val: u64) -> Self {
        Self { data: [val; 8] }
    }
}

const ITERS: u64 = 10_000_000;

fn send_t(sender: Sender<Msg>) {
    for n in 0..ITERS {
        sender.send(Msg::new(n)).unwrap();
    }
}

fn recv_t(receiver: Receiver<Msg>) {
    for _n in 0..ITERS {
        let _msg = receiver.recv().unwrap();
    }
}

pub fn test_mpmc() {
    use crossbeam_channel::bounded;
    use std::thread;

    let (s1, r1) = bounded(64);
    let (s2, r2) = (s1.clone(), r1.clone());
    let (s3, r3) = (s1.clone(), r1.clone());

    let start = Instant::now();

    let t1 = thread::spawn(move || {
        send_t(s1);
    });
    let t2 = thread::spawn(move || {
        send_t(s2);
    });
    let t3 = thread::spawn(move || {
        send_t(s3);
    });
    let t4 = thread::spawn(move || {
        recv_t(r1);
    });
    let t5 = thread::spawn(move || {
        recv_t(r2);
    });
    let t6 = thread::spawn(move || {
        recv_t(r3);
    });

    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();
    t4.join().unwrap();
    t5.join().unwrap();
    t6.join().unwrap();

    let elapsed = start.elapsed();
    let cpu_usage = moto_runtime::util::get_cpu_usage();

    println!(
        "test_mpmc: {:.3} MIOPS",
        ((ITERS * 3) as f64) / elapsed.as_secs_f64() / (1000.0 * 1000.0)
    );
    print!("\tcpu usage: ");
    for n in &cpu_usage {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
}

pub fn test_array_queue() {
    use moto_runtime::util::ArrayQueue;

    let queue = std::sync::Arc::new(ArrayQueue::<Msg>::new(128));
    let queue_2 = queue.clone();

    let start = Instant::now();
    let sender = std::thread::spawn(move || {
        for n in 0..ITERS {
            loop {
                if queue_2.push(Msg::new(n)).is_ok() {
                    break;
                }
            }
        }
    });

    // Receive inline.
    for _n in 0..ITERS {
        loop {
            if queue.pop().is_some() {
                break;
            }
        }
    }

    sender.join().unwrap();
    let elapsed = start.elapsed();
    let cpu_usage = moto_runtime::util::get_cpu_usage();

    println!(
        "test_array_queue: {:.3} MIOPS",
        (ITERS as f64) / elapsed.as_secs_f64() / (1000.0 * 1000.0)
    );
    print!("\tcpu usage: ");
    for n in &cpu_usage {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
}
