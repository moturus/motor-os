// In-kernel tracing.
use core::sync::atomic::*;

use alloc::boxed::Box;

use crate::{
    arch::time::Instant,
    config::{uCpus, TRACE_BUFFER_SIZE},
};

use super::{StaticPerCpu, StaticRef};

const _: () = assert!(TRACE_BUFFER_SIZE.is_power_of_two());

#[derive(Copy, Clone, Default)]
struct TraceRecord {
    ts: Instant,
    event: &'static str,
    arg0: u64,
    arg1: u64,
    arg2: u64,
}

impl TraceRecord {
    fn new(event: &'static str, arg0: u64, arg1: u64, arg2: u64) -> Self {
        Self {
            ts: Instant::now(),
            event,
            arg0,
            arg1,
            arg2,
        }
    }

    fn dump(&self, cpu: uCpus) {
        crate::write_serial!(
            "{} {}: {} 0x{:x} 0x{:x} 0x{:x}\n",
            self.ts.as_u64(),
            cpu,
            self.event,
            self.arg0,
            self.arg1,
            self.arg2
        );
    }
}

struct TraceBuffer {
    next_record: AtomicUsize,
    traces: [TraceRecord; TRACE_BUFFER_SIZE],
}

impl TraceBuffer {
    fn new() -> &'static mut Self {
        Box::leak(Box::new(TraceBuffer {
            next_record: AtomicUsize::new(0),
            traces: [TraceRecord::default(); TRACE_BUFFER_SIZE],
        }))
    }

    fn add_trace(&mut self, event: &'static str, arg0: u64, arg1: u64, arg2: u64) {
        let idx = self.next_record.fetch_add(1, Ordering::Relaxed);
        self.traces[idx & (TRACE_BUFFER_SIZE - 1)] = TraceRecord::new(event, arg0, arg1, arg2)
    }

    fn dump(cpu: uCpus, buffer: &Self) {
        crate::write_serial!("\nTRACE DUMP for CPU {}:\n\n", cpu);
        let next = buffer.next_record.load(Ordering::Acquire);
        if next <= TRACE_BUFFER_SIZE {
            for idx in 0..next {
                buffer.traces[idx].dump(cpu);
            }
        } else {
            let next = next & (TRACE_BUFFER_SIZE - 1);
            for idx in next..TRACE_BUFFER_SIZE {
                buffer.traces[idx].dump(cpu);
            }
            for idx in 0..next {
                buffer.traces[idx].dump(cpu);
            }
        }
    }
}

struct Tracer {
    tracing: AtomicBool,
    buffers: StaticPerCpu<TraceBuffer>,
}

impl Tracer {
    fn stop_tracing(&self) {
        self.tracing.store(false, Ordering::Release);
    }
}

static TRACER: StaticRef<Tracer> = StaticRef::default_const();

pub fn trace(event: &'static str, arg0: u64, arg1: u64, arg2: u64) {
    let tracer = TRACER.get();
    if tracer.is_none() {
        return;
    }

    // Safe because we just checked for is_none() above.
    let tracer = unsafe { tracer.unwrap_unchecked() };
    if !tracer.tracing.load(Ordering::Relaxed) {
        return;
    }
    let buffer = match tracer.buffers.get() {
        Some(buf) => buf,
        None => {
            let buf = TraceBuffer::new();
            tracer.buffers.set_per_cpu(buf)
        }
    };

    buffer.add_trace(event, arg0, arg1, arg2)
}

pub fn trace_irq(irq: u64, arg1: u64, arg2: u64) {
    let tracer = TRACER.get();
    if tracer.is_none() {
        return;
    }

    // Safe because we just checked for is_none() above.
    let tracer = unsafe { tracer.unwrap_unchecked() };
    if !tracer.tracing.load(Ordering::Relaxed) {
        return;
    }
    let buffer = match tracer.buffers.get() {
        Some(buf) => buf,
        None => {
            return; // Don't allocate in IRQ.
        }
    };

    buffer.add_trace("irq", irq, arg1, arg2)
}

pub fn start() {
    assert!(!TRACER.is_set());

    TRACER.set(Box::leak(Box::new(Tracer {
        tracing: AtomicBool::new(true),
        buffers: StaticPerCpu::new(),
    })))
}

pub fn stop() {
    if let Some(tracer) = TRACER.get() {
        tracer.stop_tracing();
    }
}

// NOTE: might be called from an IRQ context.
pub fn dump() {
    static DUMPING: AtomicBool = AtomicBool::new(false);
    if DUMPING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let tracer = TRACER.get();
    if tracer.is_none() {
        crate::write_serial!("tracing::dump(): tracing not enabled.\n");
        return;
    }

    let tracer = unsafe { tracer.unwrap_unchecked() };
    tracer.stop_tracing();

    let mut dump = |cpu: uCpus, buffer: &TraceBuffer| -> bool {
        TraceBuffer::dump(cpu, buffer);
        false
    };

    tracer.buffers.for_each_cpu(&mut dump);
}
