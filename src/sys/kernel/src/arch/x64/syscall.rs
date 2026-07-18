use crate::uspace::process::Thread;
use crate::uspace::process::ThreadOffCpuReason;
use core::arch::asm;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[macro_export]
macro_rules! push_preserved_registers {
    () => {
        "
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
    "
    };
}

#[macro_export]
macro_rules! pop_preserved_registers {
    () => {
        "
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
    "
    };
}

#[macro_export]
macro_rules! push_scratch_registers {
    () => {
        "
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
    "
    };
}

#[macro_export]
macro_rules! pop_scratch_registers {
    () => {
        "
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
    "
    };
}

#[macro_export]
macro_rules! chv_debug {
    () => {
        "
        push rax
        mov al, 13
        out 0x80, al
        pop rax
    "
    };
}

use moto_sys::caps::CAP_IO_MANAGER;
pub use pop_preserved_registers;
pub use pop_scratch_registers;
pub use push_preserved_registers;
pub use push_scratch_registers;

use super::irq::IrqStack;

pub fn init() {
    let syscall_handler_addr = syscall_handler_asm as *const () as usize as u64;
    let syscall_handler_addr_lo = syscall_handler_addr & 0xff_ff_ff_ff;
    let syscall_handler_addr_hi = syscall_handler_addr >> 32;

    unsafe {
        asm!(
            // IA32_FMASK. Purpose unknown.
            "
                mov ecx, 0xc0000084
                mov eax, 0x300
                xor edx, edx
                wrmsr
            ",

            // Store the address of our syscall handler. IA32_LSTAR.
            "
                mov ecx, 0xc0000082
                mov rax, rdi
                mov rdx, rsi
                wrmsr
                xor edx, edx
            ",

            // Related to GDT. IA32_STAR. Purpose unknown.
            "
                mov rcx, 0xc0000081
                rdmsr
                mov edx, 0x230008
                wrmsr
            ",

            // Enable syscall/sysret. IA32_EFER.
            "
                mov rcx, 0xc0000080
                rdmsr
                or eax, 1
                wrmsr
            ",

            in("rdi") syscall_handler_addr_lo,
            in("rsi") syscall_handler_addr_hi,
            out("rcx") _,
            out("rdx") _,
            options(nostack)
        )
    };
}

// TCB: a pointer to TCB lives in GS[32] on amd64.
#[repr(C, align(8))]
pub struct ThreadControlBlock {
    rip: u64,                 // [ 0] user instruction pointer
    user_rsp: u64,            // [ 8] user stack pointer
    user_page_table: u64,     // [16] user page table (L4 address)
    syscall_stack_start: u64, // [24]
    syscall_rsp: u64,         // [32] stack pointer for the in-kernel part of syscalls
    rflags: u64,              // [40] rflags
    user_rbp: u64,            // [48] user rbp; used for remote debugging.

    pf_addr: Option<u64>,

    irq_stack: IrqStack,

    // crate::uspace::process::Thread that owns this TCB.
    // As struct Thread is !Unpin and owns this TCB, this is safe.
    owner: *const Thread,

    in_syscall: AtomicBool,
    xsave: xsave::XSave,

    // MXCSR (low 32 bits) + x87 control word (next 16), saved in pause()
    // and restored in resume(): both are callee-saved in the SysV ABI, so
    // user code legally assumes they survive a syscall wrapper, but the
    // pause/resume path skips xsave/xrstor entirely (S10).
    fp_env: AtomicU64,
}

impl ThreadControlBlock {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            user_rsp: 0,
            rip: 0,
            user_page_table: 0,
            owner: core::ptr::null(),
            syscall_stack_start: 0,
            syscall_rsp: 0,
            rflags: 0b1_000_000_010, // Parity + interrupt.
            user_rbp: 0,
            pf_addr: None,
            in_syscall: AtomicBool::new(false),
            irq_stack: IrqStack::default(),
            xsave: xsave::XSave::default(),
            fp_env: AtomicU64::new(0),
        }
    }

    // See the fp_env field comment. The kernel is soft-float, so between
    // syscall entry and pause() (and between resume() and sysret) nothing
    // touches the FP environment: the values saved/restored here are the
    // user thread's.
    fn save_fp_env(&self) {
        let mut mxcsr: u32 = 0;
        let mut fcw: u16 = 0;
        unsafe {
            asm!(
                "stmxcsr [{0}]",
                "fnstcw [{1}]",
                in(reg) &mut mxcsr,
                in(reg) &mut fcw,
                options(nostack, preserves_flags)
            );
        }
        self.fp_env.store(
            (mxcsr as u64) | ((fcw as u64) << 32),
            Ordering::Relaxed,
        );
    }

    fn restore_fp_env(&self) {
        let fp_env = self.fp_env.load(Ordering::Relaxed);
        let mxcsr: u32 = fp_env as u32;
        let fcw: u16 = (fp_env >> 32) as u16;
        unsafe {
            asm!(
                "ldmxcsr [{0}]",
                "fldcw [{1}]",
                in(reg) &mxcsr,
                in(reg) &fcw,
                options(nostack, preserves_flags)
            );
        }
    }

    pub fn init(
        &mut self,
        owner: *const Thread,
        rip: u64,
        rsp: u64,
        syscall_stack_start: u64,
        upt: u64,
    ) {
        assert!(self.owner.is_null());
        self.owner = owner;
        self.rip = rip;
        self.user_rsp = rsp;
        self.syscall_stack_start = syscall_stack_start;
        self.user_page_table = upt;

        if self.owner().capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0 {
            self.rflags |= 3 << 12; // IOPL
        }
    }

    fn owner(&self) -> &Thread {
        unsafe { self.owner.as_ref().unwrap() }
    }

    pub fn rip(&self) -> u64 {
        self.rip
    }

    // Checks that IF flag is set.
    pub fn check_sti(&self) {
        assert_ne!(0, self.rflags & (1 << 9));
    }

    pub fn rbp(&self) -> u64 {
        self.user_rbp
    }

    fn to_addr(&self) -> u64 {
        self as *const ThreadControlBlock as usize as u64
    }

    pub fn pf_addr_error_code(&self) -> Option<(u64, u64)> {
        self.pf_addr
            .map(|pf_addr| (pf_addr, self.irq_stack.error_code))
    }

    unsafe fn from_addr(addr: u64) -> &'static mut Self {
        let ptr = addr as usize as *mut ThreadControlBlock;
        ptr.as_mut().unwrap()
    }

    pub fn spawn_usermode_thread(&mut self, arg: u64) -> ThreadOffCpuReason {
        crate::sched::ensure_preemption_timer();
        self.owner().process_stats.start_cpu_usage_uspace();

        self.owner().trace("spawn_usermode_thread", arg, 0);
        crate::util::full_fence(); // The kernel does a #PF without this.

        assert_ne!(0, self.user_page_table);
        assert!(!self.in_syscall.load(Ordering::Relaxed));
        self.check_sti();

        super::install_page_table(self.user_page_table);
        self.set_fs();
        self.xrstor();

        let mut ret: u64;
        let mut maybe_addr: u64;
        unsafe {
            asm!(
                // We need to `call` spawn_usermode_thread_asm instead of just inlining
                // its body here because we need the matching `ret` to work properly later.
                "call rax",
                in("rax") spawn_usermode_thread_asm,
                in("rdi") arg,
                in("rdx") self.to_addr(),
                lateout("rax") ret,
                lateout("rdi") _,
                lateout("rdx") _,
                lateout("rcx") _,
                lateout("rsi") maybe_addr,  // See kill_current_task().
            )
        };

        crate::util::full_fence(); // The kernel does a #PF without this.
        // W7: the thread that went off-CPU may not be `self` — a direct
        // switch chain can leave a different thread's TOCR in this frame.
        let off_tcb = unsafe { (super::GS::current_tcb() as usize as *const Self).as_ref() }.unwrap();
        off_tcb
            .owner()
            .trace("spawn_usermode_thread back", off_tcb.syscall_rsp, 0);
        off_tcb.thread_off_cpu_reason(ret, maybe_addr)
    }

    #[inline(never)]
    pub fn exit(&self) -> ! {
        // Defense in depth: a tick that fires mid-syscall re-arms itself in
        // on_timer_irq(), so the deadline should always be live here; this
        // is a cheap check (no wrmsr unless something went wrong).
        crate::sched::ensure_preemption_timer();
        self.owner().process_stats.stop_cpu_usage_kernel();
        self.owner().process_stats.start_cpu_usage_uspace();
        #[cfg(debug_assertions)]
        debug_assert!(super::is_kernel_rsp());
        debug_assert!(self.in_syscall.load(Ordering::Relaxed));
        unsafe { syscall_exit_asm() }
    }

    #[inline(never)]
    pub fn die(&self, tocr: u64, addr: u64) -> ! {
        self.owner().trace("TCP::die()", 0, 0);
        self.owner().process_stats.stop_cpu_usage_kernel();
        self.owner().process_stats.start_cpu_usage_uspace();
        debug_assert!(self.in_syscall.load(Ordering::Relaxed));
        kill_current_thread(tocr, addr)
    }

    pub fn validate_gs(&self) {
        #[cfg(debug_assertions)]
        {
            let mut val_gs_32: u64;
            unsafe {
                asm!(
                    "mov rax, gs:[32]",
                    out("rax") val_gs_32
                );
            }
            assert_eq!(val_gs_32, self.to_addr());
        }
    }

    #[cfg(debug_assertions)]
    fn do_validate_rsp(&self) -> bool {
        unsafe {
            let mut rip: u64;
            asm!("
                mov r11, [rax]
            ",
            in("rax") self.syscall_rsp + (8 * 6),
            out("r11") rip
            );

            rip & 0x400002000000 == 0x400002000000
        }
    }

    pub fn validate_rsp(&self) {
        #[cfg(debug_assertions)]
        if !self.do_validate_rsp() {
            // Kernel leaves are GLOBAL: a CR3 reload would not flush them.
            super::paging::flush_all_including_global();
            if self.do_validate_rsp() {
                log::error!("invalid rsp fixed by flushing KPT");
            } else {
                self.owner()
                    .trace("validate_rsp failed", self.syscall_rsp, 0);
                crate::xray::tracing::dump();
                crate::arch::arch_write_serial!("\nFATAL ERROR: validate_rsp\n");
                crate::arch::kernel_exit();
            }
        }
    }

    #[inline(never)]
    pub fn pause(&self) {
        self.owner().process_stats.stop_cpu_usage_kernel();
        self.owner().process_stats.start_cpu_usage_uspace(); // see tocr re: why
        debug_assert!(self.in_syscall.load(Ordering::Relaxed));
        self.owner().trace("pause", self.syscall_rsp, 0);
        self.save_fp_env();
        crate::util::full_fence();
        self.validate_gs();
        unsafe {
            asm!(
                "call rax",
                in("rax") syscall_pause_asm,
            )
        };
        self.validate_gs();
    }

    #[inline(never)]
    pub fn resume(&self) -> ThreadOffCpuReason {
        self.owner().process_stats.start_cpu_usage_kernel();
        crate::sched::ensure_preemption_timer();
        self.owner().trace("tcb::resume", self.syscall_rsp, 0);
        self.validate_rsp();
        self.check_sti();

        debug_assert!(self.in_syscall.load(Ordering::Relaxed));

        // The thread continues its syscall and sysrets from it without any
        // CR3 switch (W6b) — install its page table now (no-op when it is
        // already current, e.g. same-process lockstep on one CPU).
        super::install_page_table(self.user_page_table);
        self.restore_fp_env();

        // Note: we don't call self.set_fs() here because it is called
        // in syscall handler (after resume)
        let mut ret: u64;
        let mut maybe_addr: u64;
        unsafe {
            asm!(
                "call rax",
                in("rax") syscall_resume_asm,
                in("rdi") self.to_addr(),
                lateout("rax") ret,
                lateout("rdi") _,
                lateout("rsi") maybe_addr,  // See kill_current_task.
            )
        };

        crate::util::full_fence();
        // W7: see spawn_usermode_thread — the off-CPU thread is gs:[32]'s
        // owner, not necessarily `self`.
        let off_tcb = unsafe { (super::GS::current_tcb() as usize as *const Self).as_ref() }.unwrap();
        off_tcb.owner().trace("tcb::resume ret", ret, maybe_addr);
        off_tcb.thread_off_cpu_reason(ret, maybe_addr)
    }

    // Called from IRQ.
    pub fn io_thread() -> bool {
        unsafe {
            let this_tcb = Self::current_tcb();
            (this_tcb.owner().capabilities() & CAP_IO_MANAGER) != 0
        }
    }

    // Called from IRQ.
    #[inline(never)]
    pub fn preempt_current_thread_irq(irq_stack: &IrqStack) -> ! {
        unsafe {
            let this_tcb = Self::current_tcb();
            this_tcb
                .owner()
                .trace("tcb::preempt_current_thread_irq", 0, 0);
            this_tcb.user_rsp = irq_stack.rsp; //irq_stack as *const _ as usize as u64;
            this_tcb.rip = irq_stack.rip;
            this_tcb.rflags = irq_stack.flags;
            this_tcb.user_rbp = irq_stack.rbp;
            this_tcb.irq_stack = *irq_stack;
            this_tcb.pf_addr = None;
            this_tcb.xsave();
        }
        crate::util::full_fence();
        preempt_current_thread_asm()
    }

    pub fn xsave(&mut self) {
        self.xsave.save();
    }

    pub fn xrstor(&self) {
        self.xsave.load();
    }

    // Called from IRQ.
    #[inline(never)]
    pub fn preempt_current_thread_pf(irq_stack: &IrqStack, pf_addr: u64) -> ! {
        unsafe {
            let this_tcb = Self::current_tcb();
            this_tcb.user_rsp = irq_stack.rsp; //irq_stack as *const _ as usize as u64;
            this_tcb.rip = irq_stack.rip;
            this_tcb.rflags = irq_stack.flags;
            this_tcb.user_rbp = irq_stack.rbp;
            this_tcb.irq_stack = *irq_stack;
            this_tcb.pf_addr = Some(pf_addr);
            // Save SSE/AVX state: resume_preempted_thread() unconditionally does
            // xrstor(), and the interrupted instruction may hold live data in
            // vector registers (e.g. a vectorized memset faulting in a lazy page).
            this_tcb.xsave();
        }
        crate::util::full_fence();
        preempt_current_thread_asm()
    }

    pub fn resume_preempted_thread(&self) -> ThreadOffCpuReason {
        crate::sched::ensure_preemption_timer();
        self.owner().process_stats.start_cpu_usage_uspace();
        self.owner().trace("tcb::resume_preempted_thread", 0, 0);
        self.check_sti();
        unsafe {
            // Must clear to clear pf_addr.
            let self_mut = (self as *const Self as usize as *mut Self)
                .as_mut()
                .unwrap();
            self_mut.pf_addr = None;
        }
        let stack_addr = &self.irq_stack as *const _ as usize as u64;

        super::install_page_table(self.user_page_table);
        self.set_fs();
        self.xrstor();

        let mut ret: u64;
        let mut maybe_addr: u64;
        unsafe {
            asm!(
                "call rax",
                in("rax") resume_preempted_thread_asm,
                in("rdi") self.to_addr(),
                in("rsi") stack_addr,
                lateout("rax") ret,
                lateout("rdi") _,
                lateout("rsi") maybe_addr,  // See kill_current_task.
            )
        };

        crate::util::full_fence();
        // W7: see spawn_usermode_thread — the off-CPU thread is gs:[32]'s
        // owner, not necessarily `self`.
        let off_tcb = unsafe { (super::GS::current_tcb() as usize as *const Self).as_ref() }.unwrap();
        off_tcb
            .owner()
            .trace("tcb::resume_preempted_thread ret", ret, maybe_addr);
        off_tcb.thread_off_cpu_reason(ret, maybe_addr)
    }

    unsafe fn current_tcb() -> &'static mut Self {
        Self::from_addr(super::GS::current_tcb())
    }

    // W7: the thread whose kernel context this CPU last saved. After a
    // resume-type call (spawn/resume/resume_preempted) returns to the
    // kernel stack, gs:[32] identifies the thread that actually went
    // off-CPU — with direct switches (switch_to) it may not be the thread
    // the frame resumed.
    pub fn off_cpu_thread() -> alloc::sync::Weak<Thread> {
        unsafe { (super::GS::current_tcb() as usize as *const Self).as_ref() }
            .unwrap()
            .owner()
            .get_weak()
    }

    // W7: direct switch — save this thread's kernel context exactly like
    // pause() and install `next`'s exactly like resume(), without bouncing
    // through the sched-loop stack. `next` must have been claimed via a
    // *_for_switch wake: Runnable, off-CPU, parked in wait()'s pause,
    // with no resume job posted anywhere. The caller
    // (wait_and_switch) parks `self` from the other side of the switch
    // (finish_direct_switch), mirroring how on_thread_paused() runs after
    // pause() has saved the context.
    #[inline(never)]
    pub fn switch_to(&self, next: &ThreadControlBlock) {
        // Mirror pause() for self...
        self.owner().process_stats.stop_cpu_usage_kernel();
        debug_assert!(self.in_syscall.load(Ordering::Relaxed));
        self.owner().trace("tcb::switch_to", next.to_addr(), 0);
        self.save_fp_env();
        // ...and resume() for next.
        next.owner().process_stats.start_cpu_usage_kernel();
        crate::sched::ensure_preemption_timer();
        next.validate_rsp();
        next.check_sti();
        debug_assert!(next.in_syscall.load(Ordering::Relaxed));
        super::install_page_table(next.user_page_table);
        next.restore_fp_env();

        crate::util::full_fence();
        self.validate_gs();
        unsafe {
            asm!(
                "call rax",
                in("rax") syscall_switch_asm,
                in("rdi") next.to_addr(),
                clobber_abi("C"),
            )
        };
        // Someone resumed us (possibly on another CPU, possibly via a
        // direct switch of their own).
        crate::util::full_fence();
        self.validate_gs();
    }

    fn set_fs(&self) {
        unsafe {
            let cpu = crate::arch::current_cpu();
            self.owner().set_last_cpu(cpu);
            self.owner()
                .user_tcb_mut()
                .current_cpu
                .store(cpu as u32, Ordering::Relaxed);
            let fsbase = self.owner().user_tcb_user_addr();
            asm!("wrfsbase {}", in(reg) fsbase, options(nostack, preserves_flags));
        }
    }

    fn thread_off_cpu_reason(&self, tocr: u64, addr: u64) -> ThreadOffCpuReason {
        self.owner().process_stats.stop_cpu_usage_uspace();

        match tocr {
            TOCR_PAUSED => ThreadOffCpuReason::Paused,
            TOCR_PREEMPTED => {
                // If the timer fires when the CPU is running a userspace thread,
                // it is preempted and ends up here.
                crate::sched::on_timer_irq();
                ThreadOffCpuReason::Preempted
            }
            TOCR_EXITED => ThreadOffCpuReason::Exited,
            TOCR_KILLED_SF => ThreadOffCpuReason::KilledSf,
            TOCR_KILLED_GPF => ThreadOffCpuReason::KilledGpf,
            TOCR_KILLED_PF => ThreadOffCpuReason::KilledPf(addr),
            TOCR_KILLED_OTHER => ThreadOffCpuReason::KilledOther,
            val => panic!("unknown Thread Off CPU Reason: 0x{:x}", val),
        }
    }
}

// Called by syscall_handler_asm.
#[no_mangle]
extern "C" fn syscall_handler_rust(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    #[cfg(debug_assertions)]
    debug_assert!(super::is_kernel_rsp());

    // rdi, rsi, rdx, rcx, r8, r9
    use crate::uspace::syscall::*;

    let mut nr_ver: u64;
    unsafe {
        asm!(
            "
            mov r14, gs:[48]
            ",
            out("r14") nr_ver,
            options(nomem, nostack)
        );
    }

    let mut args = SyscallArgs::new(nr_ver, arg0, arg1, arg2, arg3, arg4, arg5);

    let tcb = unsafe { ThreadControlBlock::from_addr(super::GS::current_tcb()) };
    assert!(tcb
        .in_syscall
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok());
    let thread = tcb.owner();

    thread.process_stats.stop_cpu_usage_uspace();
    thread.process_stats.start_cpu_usage_kernel();
    // This may block (call TCB::pause()).
    let result = do_syscall(thread, &mut args);
    thread.process_stats.stop_cpu_usage_kernel();
    thread.process_stats.start_cpu_usage_uspace();

    tcb.validate_gs();
    tcb.check_sti();

    assert!(tcb
        .in_syscall
        .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok());
    tcb.set_fs();

    let res: u64 = result.result;
    unsafe {
        asm!("nop",
            in("rdi") result.data[0],
            in("rsi") result.data[1],
            in("rdx") result.data[2],
            in("r10") result.data[3],
            in("r8" ) result.data[4],
            in("r9" ) result.data[5],
            options(nostack)
        )
    };

    res // rax
}

#[unsafe(naked)]
unsafe extern "C" fn spawn_usermode_thread_asm() {
    // rdi, rsi, rdx = TCB, rcx, r8, r9
    naked_asm!(
        "cli", // Disable interrupts; sysretq enables them.
        push_preserved_registers!(),
        "mov gs:[40], rsp",    //  ; save kernel's RSP
        "mov gs:[32], rdx",    //  ; save TCB
        "mov rcx, [rdx]",      //  ; user RIP
        "mov rsp, [rdx + 8]",  //  ; user SP
        "mov r11, [rdx + 40]", // rflags
        // CR3 already holds the UPT: installed by install_page_table() in
        // spawn_usermode_thread() (W6b).
        // "
        // 2:
        // mov eax, $36
        // mov edx, $0x3f8
        // out dx, al
        // jmp 2b
        // ",
        // rdi, rsi: args; clear other registers.
        "xor rax, rax
        xor rbx, rbx",
        //; rcx is used as user RIP
        "xor rdx, rdx",
        // rdi is used as arg
        "xor rsi, rsi",
        "xor rbp, rbp",
        // rsp is used as RSP
        "xor r8, r8
        xor r9, r9
        xor r10, r10",
        "xor r12, r12
        xor r13, r13
        xor r14, r14
        xor r15, r15",
        "fninit",
        "swapgs",
        //     "
        // mov rax, 0xbadd
        // wrgsbase rax
        // xor rax, rax
        // ",
        "sysretq",
    );
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_handler_asm() {
    naked_asm!(
        "cli", // Disable interrupts.
        // incoming arguments: rdi, rsi, rdx, r10, r8, r9
        // standard arguments: rdi, rsi, rdx, rcx, r8, r9
        // nr_version: rax
        "swapgs",

        // W6b: no CR3 switch — the kernel is fully mapped in user page
        // tables (two shared L4 slots) and IRQ handlers have always run on
        // them; syscalls now do too. The kernel TLB is GLOBAL (W6a), the
        // user TLB survives the thread's own syscalls.
        "mov gs:[48], rax",  // scratch0: nr_version

        "mov rax, gs:[32]", // TCB
        "mov [rax], rcx",  // Save user RIP in TCB for validation.

        "mov [rax + 8], rsp", // Save user RSP
        "mov [rax + 48], rbp", // Save user RBP
        "mov rsp, [rax + 24]",   // Install syscall RSP

        "push r11",     // save rflags
        "push rcx",     // save user RIP

        push_preserved_registers!(),

        "mov rcx, r10", //    ; In our (and Linux) syscall ABI, the fourth argument is r10
        "sti",
        // ----------------------------------------------------------------
        "call syscall_handler_rust",

        "cmp eax, {RES_EXIT}", //     ; RES_EXIT; have to use eax, as 0xFF_FF_FF_FF is a bad token ??!

        // See https://doc.rust-lang.org/nightly/rust-by-example/unsafe/asm.html#labels.
        // TL;DR: use only numerical values; don't use only zeroes and ones.
        "je 2f", // Exit.

        "cli", // Disable interrupts; sysretq enables them.
        pop_preserved_registers!(),

        "pop rcx", //         ; restore user RIP
        "pop r11", //         ; restore rflags


        /*
    #    ; TODO: other return values? see crate::uspace::syscall.rs
    #
    #    ; don't clear rcx - user RIP
    #    ; don't clear rdx, rdi, rsi, r8, r9, r10: these are used
    #    ; as result values for our syscall API - see syscall.rs
    #    ; xor rdx, rdx
    #    ; xor rdi, rdi
    #    ; xor rsi, rsi
    #    ; xor r8, r8
    #    ; xor r9, r9
    #    ; xor r10, r10
    #    ; don't clear r11 - user rflags
    */

        // No CR3 switch on exit either: CR3 is the thread's UPT — unchanged
        // since syscall entry, or (re)installed by TCB::resume() if the
        // thread blocked and migrated.
        // gs:[56] - scratch 1; gs:[32] - TCB
        "
        mov gs:[56], rbx
        mov rbx, gs:[32]
        mov rsp, [rbx + 8]",  // Restore user RSP.
    "mov r11, [rbx + 40]", // rflags
        "mov rbx, gs:[56]",
        // "fninit",
        "swapgs",
        "sysretq",

        // restore preserved registers
    "2:",  // Exit.
        "mov rsp, gs:[40]",   // Restore kernel RSP
        pop_preserved_registers!(),
        "mov rax, {RESULT}",
        "ret",
        RES_EXIT = const(crate::uspace::syscall::RES_EXIT),
        RESULT = const(TOCR_EXITED),
    );
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_pause_asm() {
    naked_asm!(
        // We are now in syscall, with syscall stack.
        push_preserved_registers!(),

        // Save the syscall stack RSP, restore the kernel RSP.
        // gs:[32] holds TCB; TCB[32] holds user RSP; gs:[40] holds kernel RSP.
        "
        mov rax, gs:[32]
        mov [rax + 32], rsp
        mov rsp, gs:[40]
        ",
        pop_preserved_registers!(),
        "mov rax, {RESULT}",
        "ret",
        RESULT = const(TOCR_PAUSED),
    );
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_resume_asm() {
    naked_asm!(
        // We are now in kernel.
        push_preserved_registers!(),
        // Save the kernel RSP, restore the syscall RSP.
        // gs:[32] holds TCB; TCB[32] holds user RSP; gs:[40] holds kernel RSP.
        "
        mov gs:[40], rsp
        mov gs:[32], rdi
        mov rsp, [rdi + 32]
        ",
        pop_preserved_registers!(),
        "ret",
    );
}

// W7: syscall_pause_asm's save half + syscall_resume_asm's install half,
// with no sched-loop stack bounce in between. gs:[40] (the kernel RSP) is
// deliberately untouched: the kernel stack keeps whatever resume() frame it
// had, and when the CPU eventually returns to it the TOCR is applied to the
// *current* gs:[32] owner (see off_cpu_thread), not the thread that frame
// resumed.
#[unsafe(naked)]
unsafe extern "C" fn syscall_switch_asm() {
    // rdi = target TCB.
    naked_asm!(
        push_preserved_registers!(),
        // Save this thread's syscall RSP in its TCB (gs:[32])...
        "
        mov rax, gs:[32]
        mov [rax + 32], rsp
        ",
        // ...install the target TCB and its syscall RSP. Kernel-mode IRQs
        // in this window are harmless: they never preempt and never read
        // gs:[32] (see irq_handler_inner).
        "
        mov gs:[32], rdi
        mov rsp, [rdi + 32]
        ",
        pop_preserved_registers!(),
        "ret",
    );
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_exit_asm() -> ! {
    naked_asm!(
        // Restore the kernel RSP.
        "mov rsp, gs:[40]",
        pop_preserved_registers!(),
        "mov rax, {RESULT}",
        "ret",
        RESULT = const(TOCR_EXITED),
    );
}

#[unsafe(naked)]
pub extern "C" fn kill_current_thread(tocr: u64 /* rdi */, addr: u64 /* rsi */) -> ! {
    naked_asm!(
        "cli",
        // Switch to the kernel page table (and update the gs:[64] CR3
        // shadow): the thread is dying and its process may be torn down —
        // leave its page table immediately.
        "mov rax, gs:[24]", // KPT
        "mov cr3, rax",
        "mov gs:[64], rax",
        // Restore kernel RSP.
        "mov rsp, gs:[40]",
        // eoi.
        "
        mov ecx, 0x80b
        mov eax, 0
        mov edx, 0
        wrmsr
        ",
        pop_preserved_registers!(),
        "mov rax, rdi",
        "sti",
        "ret",
    )
}

#[unsafe(naked)]
pub extern "C" fn preempt_current_thread_asm() -> ! {
    naked_asm!(
        "cli",
        // W6b: stay on the interrupted thread's UPT — the scheduler only
        // touches kernel memory (fully mapped everywhere), and the next
        // resume skips the CR3 load if it is for the same address space.
        // Dying page tables are evicted via tlb::evict_user_page_table().
        // Restore kernel RSP.
        "mov rsp, gs:[40]",
        // eoi.
        "
        mov ecx, 0x80b
        mov eax, 0
        mov edx, 0
        wrmsr
        ",
        pop_preserved_registers!(),
        "mov rax, {RESULT}",
        "sti",
        "ret",
        RESULT = const(TOCR_PREEMPTED),
    )
}

#[unsafe(naked)]
unsafe extern "C" fn resume_preempted_thread_asm() {
    naked_asm!(
        "cli", // Disable interrupts; iretq enables them.
        // We are now in kernel.
        push_preserved_registers!(),
        // Save the kernel RSP, restore user RSP.
        // gs:[32] holds TCB; rsi holds user irq stack; gs:[40] holds kernel RSP.
        "
        mov gs:[40], rsp
        mov gs:[32], rdi
        mov rsp, rsi
        ",
        super::irq::pop_irq_registers!(),
        "add rsp, 8", // See "naked_irq_handler".
        // CR3 already holds the UPT: installed by install_page_table() in
        // resume_preempted_thread() (W6b).
        "
        swapgs
        iretq
        ",
    );
}

// Thread Off Cpu Reason.
pub const TOCR_PAUSED: u64 = 1;
pub const TOCR_PREEMPTED: u64 = 2;
pub const TOCR_EXITED: u64 = 3;
pub const TOCR_KILLED_GPF: u64 = 0x1_0001;
pub const TOCR_KILLED_PF: u64 = 0x1_0002;
pub const TOCR_KILLED_SF: u64 = 0x1_0003;
pub const TOCR_KILLED_OTHER: u64 = 0x1_0004;
