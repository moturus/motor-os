extern crate self as virtio_async;
#[path = "../../../sys-io/src/runtime/fs/block_io.rs"]
mod block_io;
#[path = "../../../sys-io/src/runtime/vsock/connection.rs"]
mod connection;
#[path = "../../../sys-io/src/runtime/vsock/credit.rs"]
mod credit;
mod device;
#[path = "../../../sys-io/src/runtime/vsock/rx_buffer.rs"]
mod rx_buffer;
mod stats;
#[path = "../../../sys-io/src/runtime/vsock/stream.rs"]
mod stream;
#[path = "../../../sys-io/src/runtime/virtio_capacity.rs"]
mod virtio_capacity;
#[path = "../../../sys-io/src/runtime/vsock/admission.rs"]
mod vsock_admission;
pub(crate) use device::{BlockDevice, RawCompletion};
pub(crate) use real_virtio_async::vsock as vsock_wire;

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
    test_vsock_stream_buffer();
    test_vsock_established_stream();
    test_vsock_connection();
    test_vsock_admission();
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
    use credit::{CreditAdvertisement as Ad, CreditError as Error, CreditState};

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

fn test_vsock_stream_buffer() {
    use credit::{CreditAdvertisement as Ad, CreditError};
    use rx_buffer::StreamBuffer;

    let mut stream = StreamBuffer::new(8).unwrap();
    assert_eq!(
        stream.credit().local_advertisement(),
        Ad {
            buf_alloc: 8,
            fwd_cnt: 0
        }
    );
    stream.try_append_packet(b"abc").unwrap();
    stream.try_append_packet(b"d").unwrap();
    stream.try_append_packet(b"ef").unwrap();
    assert_eq!(stream.credit().rx_allowance(), 2);

    let before = stream.credit().local_advertisement();
    assert_eq!(
        stream.try_append_packet(b"XYZ"),
        Err(CreditError::ReceiveCapacityExceeded)
    );
    assert_eq!(stream.credit().local_advertisement(), before);
    assert_eq!(stream.credit().rx_allowance(), 2);

    let mut empty = [];
    assert_eq!(stream.copy_into_reserved(&mut empty), 0);
    stream.try_append_packet(b"").unwrap();
    assert_eq!(stream.credit().local_advertisement(), before);

    let mut first = [0; 4];
    assert_eq!(stream.copy_into_reserved(&mut first), 4);
    assert_eq!(&first, b"abcd");
    assert_eq!(
        stream.credit().local_advertisement(),
        Ad {
            buf_alloc: 8,
            fwd_cnt: 4
        }
    );

    for packet in [b"g".as_slice(), b"hi", b"jkl"] {
        stream.try_append_packet(packet).unwrap();
    }
    assert_eq!(stream.credit().rx_allowance(), 0);

    let mut one = [0];
    assert_eq!(stream.copy_into_reserved(&mut one), 1);
    assert_eq!(&one, b"e");
    let mut two = [0; 2];
    assert_eq!(stream.copy_into_reserved(&mut two), 2);
    assert_eq!(&two, b"fg");
    let mut rest = [0; 5];
    assert_eq!(stream.copy_into_reserved(&mut rest), 5);
    assert_eq!(&rest, b"hijkl");
    assert_eq!(stream.credit().rx_allowance(), 8);
    assert_eq!(stream.credit().local_advertisement().fwd_cnt, 12);

    stream
        .update_peer(Ad {
            buf_alloc: 3,
            fwd_cnt: 0,
        })
        .unwrap();
    stream.charge_tx_after_publish(2).unwrap();
    assert_eq!(stream.credit().tx_allowance(), 1);

    let mut independent = StreamBuffer::new(3).unwrap();
    independent.try_append_packet(b"xy").unwrap();
    assert_eq!(independent.credit().rx_allowance(), 1);
    let mut page_prefix = [0xa5; 5];
    assert_eq!(independent.copy_into_reserved(&mut page_prefix), 2);
    assert_eq!(&page_prefix[..2], b"xy");
    assert_eq!(&page_prefix[2..], &[0xa5; 3]);
    assert_eq!(independent.credit().local_advertisement().fwd_cnt, 2);
    assert_eq!(independent.copy_into_reserved(&mut page_prefix), 0);
    assert_eq!(page_prefix, [b'x', b'y', 0xa5, 0xa5, 0xa5]);
    assert_eq!(independent.credit().local_advertisement().fwd_cnt, 2);
    assert_eq!(stream.credit().rx_allowance(), 8);

    let mut zero = StreamBuffer::new(0).unwrap();
    zero.try_append_packet(b"").unwrap();
    assert_eq!(
        zero.try_append_packet(b"z"),
        Err(CreditError::ReceiveCapacityExceeded)
    );
    assert_eq!(zero.copy_into_reserved(&mut one), 0);
    assert_eq!(zero.credit().local_advertisement().fwd_cnt, 0);

    if usize::BITS > u32::BITS {
        let too_large = usize::try_from(u32::MAX).unwrap().checked_add(1).unwrap();
        let err = match StreamBuffer::new(too_large) {
            Ok(_) => panic!("accepted a capacity larger than the wire field"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}

fn test_vsock_established_stream() {
    use credit::{CreditAdvertisement as Ad, CreditError};
    use stream::{EstablishedStream, ReadOutcome};

    let mut stream = EstablishedStream::new().unwrap();
    let peer = Ad {
        buf_alloc: 16,
        fwd_cnt: 0,
    };
    stream.try_receive_packet(peer, b"accepted").unwrap();
    stream.charge_tx_after_publish(6).unwrap();
    assert_eq!(stream.credit().tx_allowance(), 10);
    assert!(stream.accepts_new_writes());
    stream
        .update_peer_credit(Ad {
            buf_alloc: 20,
            fwd_cnt: 2,
        })
        .unwrap();
    assert_eq!(stream.credit().tx_allowance(), 16);

    let invalid = Ad {
        buf_alloc: 64,
        fwd_cnt: 7,
    };
    assert_eq!(
        stream.try_receive_packet(invalid, b"rejected"),
        Err(CreditError::PeerForwardedBeyondSent)
    );
    assert_eq!(stream.credit().tx_allowance(), 16);
    assert!(!stream.accepts_new_writes());

    let mut bytes = [0; 16];
    assert_eq!(
        stream.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(8)
    );
    assert_eq!(&bytes[..8], b"accepted");
    assert_eq!(
        stream.read_into_reserved(&mut bytes),
        ReadOutcome::ConnectionReset
    );

    let mut independent = EstablishedStream::new().unwrap();
    assert!(independent.accepts_new_writes());
    assert_eq!(
        independent.read_into_reserved(&mut bytes),
        ReadOutcome::Pending
    );
    independent.try_receive_packet(peer, b"still live").unwrap();
    assert_eq!(
        independent.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(10)
    );
    assert_eq!(&bytes[..10], b"still live");

    let mut receive_only = EstablishedStream::new().unwrap();
    receive_only.peer_shutdown(true, false);
    assert!(!receive_only.accepts_new_writes());
    assert_eq!(
        receive_only.read_into_reserved(&mut bytes),
        ReadOutcome::Pending
    );
    receive_only.try_receive_packet(peer, b"readable").unwrap();
    assert_eq!(
        receive_only.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(8)
    );
    assert_eq!(&bytes[..8], b"readable");
    assert_eq!(
        receive_only.read_into_reserved(&mut bytes),
        ReadOutcome::Pending
    );

    let mut shutdown = EstablishedStream::new().unwrap();
    shutdown.try_receive_packet(peer, b"drain").unwrap();
    shutdown.peer_shutdown(false, false);
    assert!(shutdown.accepts_new_writes());
    shutdown.peer_shutdown(false, true);
    assert!(shutdown.accepts_new_writes());
    assert_eq!(
        shutdown.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(5)
    );
    assert_eq!(&bytes[..5], b"drain");
    assert_eq!(shutdown.read_into_reserved(&mut bytes), ReadOutcome::Eof);
    shutdown.peer_shutdown(true, false);
    assert!(!shutdown.accepts_new_writes());
    shutdown.peer_shutdown(false, false);
    assert!(!shutdown.accepts_new_writes());
    assert_eq!(shutdown.read_into_reserved(&mut bytes), ReadOutcome::Eof);

    let mut reset = EstablishedStream::new().unwrap();
    reset.try_receive_packet(peer, b"before reset").unwrap();
    reset.peer_reset();
    assert_eq!(
        reset.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(12)
    );
    assert_eq!(&bytes[..12], b"before reset");
    assert_eq!(
        reset.read_into_reserved(&mut bytes),
        ReadOutcome::ConnectionReset
    );
    let mut empty = [];
    assert_eq!(reset.read_into_reserved(&mut empty), ReadOutcome::Copied(0));

    const CAPACITY: usize = 128 * 1024;
    let mut capacity = EstablishedStream::new().unwrap();
    let full = vec![0x5a; CAPACITY];
    capacity
        .try_receive_packet(
            Ad {
                buf_alloc: 23,
                fwd_cnt: 0,
            },
            &full,
        )
        .unwrap();
    assert_eq!(capacity.credit().rx_allowance(), 0);
    assert_eq!(capacity.credit().tx_allowance(), 23);
    assert_eq!(
        capacity.try_receive_packet(
            Ad {
                buf_alloc: 99,
                fwd_cnt: 0,
            },
            b"x"
        ),
        Err(CreditError::ReceiveCapacityExceeded)
    );
    assert_eq!(capacity.credit().rx_allowance(), 0);
    assert_eq!(capacity.credit().tx_allowance(), 23);
    let mut copied = vec![0; CAPACITY];
    assert_eq!(
        capacity.read_into_reserved(&mut copied),
        ReadOutcome::Copied(CAPACITY)
    );
    assert_eq!(copied, full);
}

fn test_vsock_connection() {
    use connection::{Connection, ConnectionPhase as Phase, ReceiveOutcome as Rx, TerminalCause};
    use stream::ReadOutcome;
    use vsock_wire::{Operation, PacketHeader, SHUTDOWN_RECEIVE, SHUTDOWN_SEND, SocketType};

    let packet = |operation, len, flags, buf_alloc, fwd_cnt| PacketHeader {
        src_cid: 2,
        dst_cid: 3,
        src_port: 70_000,
        dst_port: 80_000,
        len,
        socket_type: SocketType::Stream,
        operation,
        flags,
        buf_alloc,
        fwd_cnt,
    };
    let request = packet(Operation::Request, 0, 0, 32, 0);
    let reset = packet(Operation::Reset, 0, 0, 0, 0);

    let mut outgoing = Connection::new_outgoing().unwrap();
    assert_eq!(outgoing.phase(), Phase::Connecting);
    let response = packet(Operation::Response, 0, 0, 64, 0);
    assert_eq!(outgoing.receive(&response, b""), Rx::Connected);
    assert_eq!(outgoing.phase(), Phase::Established);
    assert_eq!(outgoing.credit().tx_allowance(), 64);
    assert_eq!(outgoing.receive(&response, b""), Rx::SendReset);
    assert_eq!(
        outgoing.phase(),
        Phase::Terminal(TerminalCause::ConnectionReset)
    );
    assert_eq!(outgoing.receive(&reset, b""), Rx::None);
    assert_eq!(
        outgoing.phase(),
        Phase::Terminal(TerminalCause::ConnectionReset)
    );
    assert_eq!(
        outgoing.receive(&packet(Operation::CreditUpdate, 0, 0, 64, 0), b""),
        Rx::SendReset
    );

    let mut refused = Connection::new_outgoing().unwrap();
    assert_eq!(refused.receive(&reset, b""), Rx::None);
    assert_eq!(refused.phase(), Phase::Terminal(TerminalCause::Refused));
    let mut premature = Connection::new_outgoing().unwrap();
    assert_eq!(
        premature.receive(&packet(Operation::ReadWrite, 1, 0, 32, 0), b"x"),
        Rx::SendReset
    );
    assert_eq!(premature.phase(), Phase::Terminal(TerminalCause::Refused));

    let mut incoming = Connection::new_incoming(&request).unwrap();
    assert_eq!(incoming.phase(), Phase::Established);
    assert_eq!(
        incoming.receive(&packet(Operation::ReadWrite, 5, 0, 32, 0), b"early"),
        Rx::None
    );
    incoming.charge_tx_after_publish(4).unwrap();
    assert_eq!(
        incoming.receive(&packet(Operation::CreditUpdate, 0, 0, 40, 2), b""),
        Rx::None
    );
    assert_eq!(incoming.credit().tx_allowance(), 38);
    assert_eq!(
        incoming.receive(&packet(Operation::CreditRequest, 0, 0, 40, 2), b""),
        Rx::SendCreditUpdate
    );
    assert_eq!(
        incoming.receive(
            &packet(Operation::Shutdown, 0, SHUTDOWN_RECEIVE, 40, 2),
            b""
        ),
        Rx::None
    );
    assert!(!incoming.accepts_new_writes());
    assert_eq!(
        incoming.receive(&packet(Operation::Shutdown, 0, 0, 40, 2), b""),
        Rx::None
    );
    assert!(!incoming.accepts_new_writes());
    assert_eq!(
        incoming.receive(&packet(Operation::Shutdown, 0, SHUTDOWN_SEND, 40, 2), b""),
        Rx::None
    );
    assert_eq!(
        incoming.receive(&packet(Operation::ReadWrite, 0, 0, 40, 2), b""),
        Rx::None
    );
    let mut bytes = [0; 16];
    assert_eq!(
        incoming.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(5)
    );
    assert_eq!(&bytes[..5], b"early");
    assert_eq!(incoming.read_into_reserved(&mut bytes), ReadOutcome::Eof);
    assert_eq!(
        incoming.receive(&packet(Operation::ReadWrite, 4, 0, 40, 2), b"late"),
        Rx::SendReset
    );
    assert_eq!(
        incoming.read_into_reserved(&mut bytes),
        ReadOutcome::ConnectionReset
    );

    let mut invalid = Connection::new_incoming(&request).unwrap();
    assert_eq!(
        invalid.receive(&packet(Operation::ReadWrite, 5, 0, 32, 0), b"prior"),
        Rx::None
    );
    invalid.charge_tx_after_publish(2).unwrap();
    let local_before = invalid.credit().local_advertisement();
    assert_eq!(invalid.credit().tx_allowance(), 30);
    assert_eq!(
        invalid.receive(&packet(Operation::ReadWrite, 3, 0, 99, 3), b"bad"),
        Rx::SendReset
    );
    assert_eq!(invalid.credit().local_advertisement(), local_before);
    assert_eq!(invalid.credit().tx_allowance(), 30);
    assert_eq!(
        invalid.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(5)
    );
    assert_eq!(&bytes[..5], b"prior");
    assert_eq!(
        invalid.read_into_reserved(&mut bytes),
        ReadOutcome::ConnectionReset
    );

    let mut over_credit = Connection::new_incoming(&request).unwrap();
    assert_eq!(
        over_credit.receive(&packet(Operation::ReadWrite, 2, 0, 32, 0), b"ok"),
        Rx::None
    );
    let local_before = over_credit.credit().local_advertisement();
    let oversized = vec![0xa5; 128 * 1024];
    assert_eq!(
        over_credit.receive(
            &packet(Operation::ReadWrite, oversized.len() as u32, 0, 77, 0),
            &oversized
        ),
        Rx::SendReset
    );
    assert_eq!(over_credit.credit().local_advertisement(), local_before);
    assert_eq!(over_credit.credit().tx_allowance(), 32);
    assert_eq!(
        over_credit.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(2)
    );
    assert_eq!(&bytes[..2], b"ok");
    assert_eq!(
        over_credit.read_into_reserved(&mut bytes),
        ReadOutcome::ConnectionReset
    );

    let mut independent = Connection::new_incoming(&request).unwrap();
    assert_eq!(
        independent.receive(&packet(Operation::ReadWrite, 4, 0, 32, 0), b"live"),
        Rx::None
    );
    assert_eq!(independent.phase(), Phase::Established);
    assert_eq!(independent.receive(&request, b""), Rx::SendReset);
    assert_eq!(
        independent.read_into_reserved(&mut bytes),
        ReadOutcome::Copied(4)
    );
    assert_eq!(&bytes[..4], b"live");
    assert_eq!(
        independent.read_into_reserved(&mut bytes),
        ReadOutcome::ConnectionReset
    );
}

fn test_vsock_admission() {
    use vsock_admission::{AdmissionError, ConnectionTuple, TupleIndex, VsockAddr, find_ephemeral};

    let addr = |cid, port| VsockAddr { cid, port };
    let mut index = TupleIndex::new();
    assert_eq!(index.reserve_listener(1, 3, 70_000), Ok(70_000));
    assert_eq!(index.listener_socket(addr(3, 70_000)), Some(1));
    let unchanged = index.counts();
    assert_eq!(
        index.reserve_listener(2, 3, 70_000),
        Err(AdmissionError::PortInUse)
    );
    assert_eq!(
        index.reserve_listener(1, 3, 70_001),
        Err(AdmissionError::SocketIdInUse)
    );
    assert_eq!(
        index.reserve_listener(2, 3, u32::MAX),
        Err(AdmissionError::InvalidPort)
    );
    assert_eq!(index.counts(), unchanged);

    assert_eq!(index.reserve_listener(2, 3, 49_152), Ok(49_152));
    assert_eq!(
        index.reserve_listener(1, 3, 0),
        Err(AdmissionError::SocketIdInUse)
    );
    assert_eq!(index.reserve_listener(7, 3, 0), Ok(49_153));
    let peer = addr(5, 80_000);
    let outgoing = index.reserve_outgoing(3, 3, peer).unwrap();
    assert_eq!(outgoing.local, addr(3, 49_154));
    assert_eq!(index.stream_socket(outgoing), Some(3));
    let tuple = |local_cid, local_port, peer_cid, peer_port| ConnectionTuple {
        local: addr(local_cid, local_port),
        peer: addr(peer_cid, peer_port),
    };
    for different in [
        tuple(4, outgoing.local.port, peer.cid, peer.port),
        tuple(3, outgoing.local.port, 6, peer.port),
        tuple(3, outgoing.local.port, peer.cid, peer.port + 1),
    ] {
        assert_eq!(index.stream_socket(different), None);
    }
    let unchanged = index.counts();
    assert_eq!(
        index.reserve_outgoing(4, 3, addr(5, 0)),
        Err(AdmissionError::InvalidPort)
    );
    assert_eq!(
        index.reserve_outgoing(4, 3, addr(5, u32::MAX)),
        Err(AdmissionError::InvalidPort)
    );
    assert_eq!(index.counts(), unchanged);

    let child = index.reserve_accepted(1, 4, addr(8, 90_000)).unwrap();
    let sibling = index.reserve_accepted(1, 5, addr(9, 90_000)).unwrap();
    assert_eq!(child.local, addr(3, 70_000));
    let unchanged = index.counts();
    assert_eq!(
        index.reserve_accepted(1, 6, child.peer),
        Err(AdmissionError::TupleInUse)
    );
    assert_eq!(index.counts(), unchanged);
    assert_eq!(index.remove_listener(1), Some(addr(3, 70_000)));
    assert_eq!(
        index.reserve_listener(6, 3, 70_000),
        Err(AdmissionError::PortInUse)
    );
    assert_eq!(index.remove_stream(4), Some(child));
    assert_eq!(index.remove_stream(5), Some(sibling));
    assert_eq!(index.reserve_listener(6, 3, 70_000), Ok(70_000));

    assert_eq!(
        find_ephemeral(u32::MAX - 1, |port| {
            port == u32::MAX - 1 || port == 49_152
        }),
        Some((49_153, 49_154))
    );

    let mut listeners = TupleIndex::new();
    for id in 0..32 {
        listeners
            .reserve_listener(id, 3, 100_000 + id as u32)
            .unwrap();
    }
    assert_eq!(
        listeners.reserve_listener(32, 3, 200_000),
        Err(AdmissionError::ListenerLimit)
    );
    assert_eq!(listeners.counts(), (0, 32));
    listeners.remove_listener(0).unwrap();
    assert_eq!(listeners.reserve_listener(32, 3, 200_000), Ok(200_000));

    let mut streams = TupleIndex::new();
    streams.reserve_listener(1, 3, 70_000).unwrap();
    for id in 0..64 {
        streams
            .reserve_accepted(1, id + 2, addr(id as u32 + 4, 100_000))
            .unwrap();
    }
    assert_eq!(
        streams.reserve_accepted(1, 66, addr(100, 100_000)),
        Err(AdmissionError::StreamLimit)
    );
    assert_eq!(streams.counts(), (64, 1));
    streams.remove_stream(2).unwrap();
    streams.reserve_accepted(1, 66, addr(4, 100_000)).unwrap();
    assert_eq!(streams.counts(), (64, 1));
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
