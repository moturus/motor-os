// In-kernel tracing.
use core::sync::atomic::*;

use alloc::boxed::Box;

use crate::{
    arch::time::Instant,
    config::{uCpus, TRACE_BUFFER_SIZE},
};

use crate::util::{StaticPerCpu, StaticRef};

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
        x86_64::instructions::interrupts::without_interrupts(|| {
            let idx = self.next_record.fetch_add(1, Ordering::AcqRel);
            self.traces[idx & (TRACE_BUFFER_SIZE - 1)] = TraceRecord::new(event, arg0, arg1, arg2)
        });
    }

    fn dump(cpu: uCpus, buffer: &Self) {
        x86_64::instructions::interrupts::without_interrupts(|| {
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
        });
    }
}

struct Tracer {
    tracing: AtomicBool,
    buffers: StaticPerCpu<TraceBuffer>,
}

impl Tracer {
    fn start_tracing(&self) {
        self.tracing.store(true, Ordering::Release);
    }
    fn stop_tracing(&self) {
        self.tracing.store(false, Ordering::Release);
    }
    fn is_tracing(&self) -> bool {
        self.tracing.load(Ordering::Acquire)
    }
}

static TRACER: StaticRef<Tracer> = StaticRef::default_const();

pub fn trace(event: &'static str, arg0: u64, arg1: u64, arg2: u64) {
    let Some(tracer) = TRACER.get() else {
        return;
    };
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
    let Some(tracer) = TRACER.get() else {
        return;
    };
    if !tracer.tracing.load(Ordering::Relaxed) {
        return;
    }
    let Some(buffer) = tracer.buffers.get() else {
        return; // Don't allocate in IRQ.
    };

    buffer.add_trace("irq", irq, arg1, arg2)
}

pub fn start() {
    assert!(!TRACER.is_set());

    TRACER.set(Box::leak(Box::new(Tracer {
        tracing: AtomicBool::new(true),
        buffers: StaticPerCpu::init(),
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
    let dumping = DUMPING.swap(true, Ordering::SeqCst);
    if dumping {
        return;
    }

    let tracer = TRACER.get();
    if tracer.is_none() {
        crate::write_serial!("tracing::dump(): tracing not enabled.\n");
        DUMPING.store(false, Ordering::Release);
        return;
    }

    let tracer = unsafe { tracer.unwrap_unchecked() };
    if !tracer.is_tracing() {
        crate::write_serial!("tracing::dump(): not tracing.\n");
        DUMPING.store(false, Ordering::Release);
        return;
    }

    let mut dump = |cpu: uCpus, buffer: &TraceBuffer| -> bool {
        TraceBuffer::dump(cpu, buffer);
        false
    };

    crate::write_serial!("tracing::dump(): starting.\n");
    tracer.stop_tracing();
    tracer.buffers.for_each_cpu(&mut dump);
    tracer.start_tracing();
    crate::write_serial!("tracing::dump(): done.\n");
    DUMPING.store(false, Ordering::Release);
}
