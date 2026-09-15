extern crate self as virtio_async;
#[path = "../../../sys-io/src/runtime/fs/block_io.rs"]
mod block_io;
mod device;
mod stats;
#[path = "../../../sys-io/src/runtime/virtio_capacity.rs"]
mod virtio_capacity;
#[path = "../../../sys-io/src/runtime/vsock/credit.rs"]
mod vsock_credit;
pub(crate) use device::{BlockDevice, RawCompletion};

use std::cell::Cell;
use std::io::ErrorKind;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};

struct Signal(AtomicBool);
impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn drive<F: Future<Output = ()>>(mut task: Pin<&mut F>) -> bool {
    let signal = Arc::new(Signal(AtomicBool::new(true)));
    let waker = Waker::from(signal.clone());
    let mut cx = Context::from_waker(&waker);
    for _ in 0..128 {
        signal.0.store(false, Ordering::Relaxed);
        if task.as_mut().poll(&mut cx).is_ready() {
            return true;
        }
        if !signal.0.load(Ordering::Relaxed) {
            return false;
        }
    }
    panic!("task did not quiesce in its bounded model step");
}

struct Buffer(Rc<Cell<usize>>);
impl Drop for Buffer {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn message(
    operation: u8,
    pages: Vec<u64>,
    reply: moto_async::oneshot::Sender<std::io::Result<()>>,
) -> block_io::Message {
    match operation {
        0 => block_io::Message::Read {
            first_sector: 80,
            pages,
            reply,
        },
        1 => block_io::Message::Write {
            first_sector: 80,
            pages,
            reply,
        },
        2 => block_io::Message::Flush { reply },
        _ => unreachable!(),
    }
}

fn scenario(operation: u8, pages: usize, seg_max: usize, capacity: usize, errors: bool) {
    let device = Rc::new(BlockDevice::new(capacity, seg_max));
    let stats = Rc::new(stats::FsStats::default());
    let (sender, receiver) = moto_async::channel(2);
    let mut task = Box::pin(block_io::run(device.clone(), receiver, stats.clone()));
    let drops = Rc::new(Cell::new(0));
    let addresses: Vec<_> = (0..pages).map(|n| 4096 * (n as u64 + 1)).collect();
    let mut send = Box::pin(block_io::send(&sender, Buffer(drops.clone()), |reply| {
        message(operation, addresses.clone(), reply)
    }));
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(mut reply)) = send.as_mut().poll(&mut cx) else {
        panic!("empty inbox did not admit request");
    };
    drop(send);
    let chunks = if operation == 2 {
        1
    } else {
        pages.div_ceil(seg_max)
    };
    assert!(!drive(task.as_mut()));
    assert_eq!(device.submissions.borrow().len(), chunks.min(capacity));
    // Closing the inbox must still drain every admitted chunk.
    drop(sender);
    for finished in 0..chunks {
        assert!(Pin::new(&mut reply).poll(&mut cx).is_pending());
        assert_eq!(drops.get(), 0);
        let (id, complete) = {
            let mut submissions = device.submissions.borrow_mut();
            let id = submissions.iter().rposition(|s| s.done.is_some()).unwrap();
            (id, submissions[id].done.take().unwrap())
        };
        let result = if errors && id == 0 {
            Err(ErrorKind::PermissionDenied.into())
        } else if errors && id == chunks - 1 {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(())
        };
        complete.send(result).unwrap();
        assert_eq!(drive(task.as_mut()), finished + 1 == chunks);
        assert!(device.live() <= capacity);
    }
    if chunks == 0 {
        assert!(drive(task.as_mut()));
    }
    let Poll::Ready((buffer, result)) = Pin::new(&mut reply).poll(&mut cx) else {
        panic!("reply did not resolve after all chunks completed");
    };
    if errors {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
    } else {
        result.unwrap();
    }
    assert_eq!(drops.get(), 0);
    drop(buffer);
    assert_eq!(drops.get(), 1);
    assert_eq!(device.live(), 0);
    let submissions = device.submissions.borrow();
    assert_eq!(submissions.len(), chunks);
    for (id, submitted) in submissions.iter().enumerate() {
        assert_eq!(submitted.operation, operation);
        assert_eq!(
            submitted.sector,
            if operation == 2 {
                0
            } else {
                80 + (id * seg_max * 8) as u64
            }
        );
        let start = id * seg_max;
        assert_eq!(
            submitted.pages,
            addresses[start..(start + seg_max).min(pages)]
        );
    }
    assert_eq!(
        stats.device_reads.get(),
        if operation == 0 { chunks as u64 } else { 0 }
    );
    assert_eq!(
        stats.device_writes.get(),
        if operation == 1 { chunks as u64 } else { 0 }
    );
}

fn admission_and_drop() {
    let (sender, receiver) = moto_async::channel(1);
    let drops = Rc::new(Cell::new(0));
    let mut cx = Context::from_waker(Waker::noop());
    // A closed inbox returns the buffer without arming a reply guard.
    drop(receiver);
    let mut send = Box::pin(block_io::send(&sender, Buffer(drops.clone()), |reply| {
        message(1, vec![4096], reply)
    }));
    let Poll::Ready(Err((buffer, error))) = send.as_mut().poll(&mut cx) else {
        panic!("closed inbox admitted data")
    };
    assert_eq!(error.kind(), ErrorKind::NotConnected);
    assert_eq!(drops.get(), 0);
    drop(buffer);
    assert_eq!(drops.get(), 1);
}

fn concurrent_requests() {
    let configs = [(0, 1_usize), (1, 17), (0, 3), (1, 0), (1, 8), (2, 0)];
    let device = Rc::new(BlockDevice::new(3, 2));
    let (sender, receiver) = moto_async::channel(2);
    let mut task = Box::pin(block_io::run(
        device.clone(),
        receiver,
        Rc::new(stats::FsStats::default()),
    ));
    let drops: Vec<_> = configs.iter().map(|_| Rc::new(Cell::new(0))).collect();
    let mut sends: Vec<_> = configs
        .iter()
        .enumerate()
        .map(|(id, &(operation, pages))| {
            let addresses = (0..pages)
                .map(|page| ((id + 1) * 0x100000 + page * 4096) as u64)
                .collect();
            Some(Box::pin(block_io::send(
                &sender,
                Buffer(drops[id].clone()),
                move |reply| message(operation, addresses, reply),
            )))
        })
        .collect();
    let mut replies: Vec<_> = configs.iter().map(|_| None).collect();
    let mut completed = [0_usize; 6];
    let mut delivered = [false; 6];
    let mut cx = Context::from_waker(Waker::noop());
    for step in 0..100 {
        for (id, send) in sends.iter_mut().enumerate() {
            if let Some(future) = send
                && let Poll::Ready(result) = future.as_mut().poll(&mut cx)
            {
                replies[id] = Some(result.unwrap_or_else(|_| panic!("inbox closed")));
                *send = None;
            }
        }
        assert!(!drive(task.as_mut()));
        assert!(device.live() <= 3);
        for (id, reply) in replies.iter_mut().enumerate() {
            if let Some(future) = reply
                && let Poll::Ready((buffer, result)) = Pin::new(future).poll(&mut cx)
            {
                let chunks = if configs[id].0 == 2 {
                    1
                } else {
                    configs[id].1.div_ceil(2)
                };
                assert_eq!(completed[id], chunks, "reply before all chunks completed");
                if id == 1 {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
                } else {
                    result.unwrap();
                }
                assert_eq!(drops[id].get(), 0);
                drop(buffer);
                assert_eq!(drops[id].get(), 1);
                *reply = None;
                delivered[id] = true;
            }
        }
        if delivered.iter().all(|done| *done) {
            drop(sends);
            drop(sender);
            assert!(drive(task.as_mut()));
            assert_eq!(device.live(), 0);
            assert_eq!(completed, [1, 9, 2, 0, 4, 1]);
            return;
        }
        let mut submissions = device.submissions.borrow_mut();
        let pending = if step % 2 == 0 {
            submissions.iter().position(|s| s.done.is_some())
        } else {
            submissions.iter().rposition(|s| s.done.is_some())
        };
        if let Some(index) = pending {
            let submission = &mut submissions[index];
            let id = submission
                .pages
                .first()
                .map_or(5, |address| (*address / 0x100000 - 1) as usize);
            assert_eq!(submission.operation, configs[id].0);
            completed[id] += 1;
            let result = if id == 1 {
                Err(ErrorKind::InvalidData.into())
            } else {
                Ok(())
            };
            submission.done.take().unwrap().send(result).unwrap();
        }
    }
    panic!("concurrent requests did not drain in 100 model steps");
}

fn runtime_wakeups() {
    use futures::{StreamExt, stream::FuturesUnordered};

    moto_async::LocalRuntime::new().block_on(async {
        let device = Rc::new(BlockDevice::new(3, 2));
        let (sender, receiver) = moto_async::channel(2);
        let (task_done, task_result) = moto_async::oneshot();
        let task_device = device.clone();
        moto_async::LocalRuntime::spawn(async move {
            block_io::run(task_device, receiver, Rc::new(stats::FsStats::default())).await;
            task_done.send(()).unwrap();
        });
        let (device_done, device_result) = moto_async::oneshot();
        let completing = device.clone();
        moto_async::LocalRuntime::spawn(async move {
            for index in 0..17 {
                let done = loop {
                    let next = {
                        let mut submissions = completing.submissions.borrow_mut();
                        let next = if index % 2 == 0 {
                            submissions.iter().position(|s| s.done.is_some())
                        } else {
                            submissions.iter().rposition(|s| s.done.is_some())
                        };
                        next.map(|id| submissions[id].done.take().unwrap())
                    };
                    if let Some(done) = next {
                        break done;
                    }
                    completing.submitted.notified().await;
                };
                // Completion must resume sleeping tasks through their actual
                // registered wakers, without the manual model's extra polls.
                moto_async::sleep(std::time::Duration::from_millis(1)).await;
                done.send(Ok(())).unwrap();
            }
            device_done.send(()).unwrap();
        });
        let drops = Rc::new(Cell::new(0));
        let mut requests = FuturesUnordered::new();
        for (operation, pages) in [(0, 1), (1, 17), (0, 3), (1, 0), (1, 8), (2, 0)] {
            let sender = sender.clone();
            let drops = drops.clone();
            requests.push(async move {
                let pages = (0..pages).map(|page| (page + 1) * 4096).collect();
                let reply = block_io::send(&sender, Buffer(drops), |reply| {
                    message(operation, pages, reply)
                })
                .await
                .unwrap_or_else(|_| panic!("inbox closed"));
                let (buffer, result) = reply.await;
                result.unwrap();
                drop(buffer);
            });
        }
        drop(sender);
        while requests.next().await.is_some() {}
        device_result.await.unwrap();
        task_result.await.unwrap();
        assert_eq!(drops.get(), 6);
        assert_eq!(device.live(), 0);
    });
}

pub fn test_premature_reply_drop() {
    let (sender, _receiver) = moto_async::channel(1);
    let mut send = Box::pin(block_io::send(&sender, (), |reply| {
        message(1, vec![4096], reply)
    }));
    let Poll::Ready(Ok(reply)) = send.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("admission failed")
    };
    drop(reply);
    panic!("early drop was accepted");
}

pub fn run_tests() {
    test_virtio_capacity();
    test_vsock_credit();
    concurrent_requests();
    runtime_wakeups();
    for operation in [0, 1] {
        for seg_max in [1, 2, 16] {
            for capacity in [1, 3] {
                for pages in [0, 1, 2, 17, 63] {
                    scenario(operation, pages, seg_max, capacity, false);
                    if pages != 0 {
                        scenario(operation, pages, seg_max, capacity, true);
                    }
                }
            }
        }
    }
    scenario(2, 0, 1, 1, false);
    admission_and_drop();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("test-virtio-reply-drop")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("block I/O reply dropped before resolving")
    );
    println!(
        "I/O task model PASS: split capacity, out-of-order errors, buffer ownership, closed inbox, fatal early drop"
    );
}

fn test_vsock_credit() {
    use vsock_credit::{CreditAdvertisement as Ad, CreditError as Error, CreditState};

    let mut credit = CreditState::new(128 * 1024).unwrap();
    assert_eq!(
        credit.local_advertisement(),
        Ad {
            buf_alloc: 128 * 1024,
            fwd_cnt: 0
        }
    );
    assert_eq!(credit.tx_allowance(), 0);
    credit.charge_tx_after_publish(0).unwrap();
    credit
        .update_peer(Ad {
            buf_alloc: 10,
            fwd_cnt: 0,
        })
        .unwrap();
    credit.charge_tx_after_publish(4).unwrap();
    assert_eq!(credit.tx_allowance(), 6);
    assert_eq!(
        credit.charge_tx_after_publish(7),
        Err(Error::TxExceedsPeerCredit)
    );
    assert_eq!(credit.tx_allowance(), 6);
    credit.charge_tx_after_publish(6).unwrap();
    assert_eq!(credit.tx_allowance(), 0);

    let mut changing = CreditState::new(8).unwrap();
    changing
        .update_peer(Ad {
            buf_alloc: 100,
            fwd_cnt: 0,
        })
        .unwrap();
    changing.charge_tx_after_publish(80).unwrap();
    changing
        .update_peer(Ad {
            buf_alloc: 120,
            fwd_cnt: 0,
        })
        .unwrap();
    assert_eq!(changing.tx_allowance(), 40);
    changing
        .update_peer(Ad {
            buf_alloc: 60,
            fwd_cnt: 0,
        })
        .unwrap();
    assert_eq!(changing.tx_allowance(), 0);
    changing
        .update_peer(Ad {
            buf_alloc: 60,
            fwd_cnt: 21,
        })
        .unwrap();
    assert_eq!(changing.tx_allowance(), 1);
    assert_eq!(
        changing.update_peer(Ad {
            buf_alloc: u32::MAX,
            fwd_cnt: 81
        }),
        Err(Error::PeerForwardedBeyondSent)
    );
    assert_eq!(changing.tx_allowance(), 1);
    changing
        .update_peer(Ad {
            buf_alloc: 60,
            fwd_cnt: 22,
        })
        .unwrap();
    assert_eq!(changing.tx_allowance(), 2);

    let mut wrapping = CreditState::new(1).unwrap();
    wrapping
        .update_peer(Ad {
            buf_alloc: u32::MAX,
            fwd_cnt: 0,
        })
        .unwrap();
    wrapping.charge_tx_after_publish(u32::MAX - 2).unwrap();
    assert_eq!(wrapping.tx_allowance(), 2);
    wrapping
        .update_peer(Ad {
            buf_alloc: u32::MAX,
            fwd_cnt: u32::MAX - 3,
        })
        .unwrap();
    assert_eq!(wrapping.tx_allowance(), u32::MAX - 1);
    wrapping.charge_tx_after_publish(3).unwrap();
    assert_eq!(wrapping.tx_allowance(), u32::MAX - 4);
    wrapping
        .update_peer(Ad {
            buf_alloc: u32::MAX,
            fwd_cnt: u32::MAX,
        })
        .unwrap();
    assert_eq!(wrapping.tx_allowance(), u32::MAX - 1);
    wrapping
        .update_peer(Ad {
            buf_alloc: u32::MAX,
            fwd_cnt: 0,
        })
        .unwrap();
    assert_eq!(wrapping.tx_allowance(), u32::MAX);
    assert_eq!(
        wrapping.update_peer(Ad {
            buf_alloc: 17,
            fwd_cnt: 1
        }),
        Err(Error::PeerForwardedBeyondSent)
    );
    assert_eq!(wrapping.tx_allowance(), u32::MAX);

    let mut local = CreditState::new(8).unwrap();
    local.record_received(5).unwrap();
    assert_eq!(local.rx_allowance(), 3);
    assert_eq!(
        local.record_received(4),
        Err(Error::ReceiveCapacityExceeded)
    );
    assert_eq!(
        local.record_received(usize::MAX),
        Err(Error::ReceiveCapacityExceeded)
    );
    assert_eq!(
        local.record_forwarded_to_ipc(6),
        Err(Error::ForwardedBeyondBuffered)
    );
    assert_eq!(local.rx_allowance(), 3);
    local.record_forwarded_to_ipc(3).unwrap();
    assert_eq!(
        local.local_advertisement(),
        Ad {
            buf_alloc: 8,
            fwd_cnt: 3
        }
    );
    assert_eq!(local.rx_allowance(), 6);

    let max = u32::MAX as usize;
    let mut local_wrap = CreditState::new(max).unwrap();
    local_wrap.record_received(max - 1).unwrap();
    local_wrap.record_forwarded_to_ipc(max - 2).unwrap();
    local_wrap.record_received(4).unwrap();
    local_wrap.record_forwarded_to_ipc(4).unwrap();
    assert_eq!(
        local_wrap.local_advertisement(),
        Ad {
            buf_alloc: u32::MAX,
            fwd_cnt: 1
        }
    );
    assert_eq!(
        CreditState::new(max + 1).err(),
        Some(Error::CapacityTooLarge)
    );

    let mut first = CreditState::new(4).unwrap();
    let second = CreditState::new(6).unwrap();
    first.record_received(4).unwrap();
    first.record_forwarded_to_ipc(1).unwrap();
    assert_eq!(first.rx_allowance(), 1);
    assert_eq!(
        second.local_advertisement(),
        Ad {
            buf_alloc: 6,
            fwd_cnt: 0
        }
    );
    assert_eq!((second.rx_allowance(), second.tx_allowance()), (6, 0));
}

fn test_virtio_capacity() {
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

    let bump = AtomicU64::new(0);
    assert_eq!(
        virtio_capacity::reserve_mmio(&bump, 4097).unwrap(),
        (0, 8192)
    );
    assert_eq!(bump.load(Ordering::Relaxed), 8192);

    let exact_end = AtomicU64::new(virtio_capacity::MMIO_POOL_SIZE - 4096);
    assert_eq!(
        virtio_capacity::reserve_mmio(&exact_end, 1).unwrap(),
        (virtio_capacity::MMIO_POOL_SIZE - 4096, 4096)
    );
    assert_eq!(
        exact_end.load(Ordering::Relaxed),
        virtio_capacity::MMIO_POOL_SIZE
    );
    for size in [1, virtio_capacity::MMIO_POOL_SIZE + 1] {
        assert_eq!(
            virtio_capacity::reserve_mmio(&exact_end, size)
                .unwrap_err()
                .kind(),
            ErrorKind::OutOfMemory
        );
        assert_eq!(
            exact_end.load(Ordering::Relaxed),
            virtio_capacity::MMIO_POOL_SIZE
        );
    }

    let rejected = AtomicU64::new(4096);
    for size in [0, u64::MAX] {
        assert_eq!(
            virtio_capacity::reserve_mmio(&rejected, size)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(rejected.load(Ordering::Relaxed), 4096);
    }
    let overflow = AtomicU64::new(u64::MAX - 4095);
    assert_eq!(
        virtio_capacity::reserve_mmio(&overflow, 4096)
            .unwrap_err()
            .kind(),
        ErrorKind::OutOfMemory
    );
    assert_eq!(overflow.load(Ordering::Relaxed), u64::MAX - 4095);

    let topology = AtomicU64::new(0);
    // One block queue, two two-queue NICs, and the future three-queue vsock.
    for queues in [1, 2, 2, 3] {
        for _ in 0..queues {
            virtio_capacity::reserve_mmio(&topology, 12_804).unwrap();
        }
    }
    assert_eq!(topology.load(Ordering::Relaxed), 8 * 16_384);

    let irqs = AtomicU8::new(virtio_capacity::IRQ_START);
    for expected in 64..80 {
        assert_eq!(virtio_capacity::reserve_irq(&irqs).unwrap(), expected);
    }
    assert_eq!(irqs.load(Ordering::Relaxed), 80);
    assert_eq!(
        virtio_capacity::reserve_irq(&irqs).unwrap_err().kind(),
        ErrorKind::OutOfMemory
    );
    assert_eq!(irqs.load(Ordering::Relaxed), 80);
    for rejected in [63, u8::MAX] {
        let irqs = AtomicU8::new(rejected);
        assert_eq!(
            virtio_capacity::reserve_irq(&irqs).unwrap_err().kind(),
            ErrorKind::OutOfMemory
        );
        assert_eq!(irqs.load(Ordering::Relaxed), rejected);
    }
}
