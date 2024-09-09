use std::collections::VecDeque;

use clap::{Args, Parser, Subcommand};
use moto_sys::SysRay;

#[derive(Parser, Debug, Clone)]
#[command()]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Args, Debug, Clone)]
struct PrintStackArgs {
    pid: u64,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    PrintStacks(PrintStackArgs),
    Attach,
}

// TODO: there are a bunch o panics (via unwrap()) below, which
// can be triggered by the debuggee misbehaving (e.g. dying).
// We should properly handle these errors and display meaningful
// messages to the user.

const BT_DEPTH: usize = 64;

fn _get_backtrace() -> [u64; BT_DEPTH] {
    let mut backtrace: [u64; BT_DEPTH] = [0; BT_DEPTH];

    let mut rbp: u64;
    unsafe {
        core::arch::asm!(
            "mov rdx, rbp", out("rdx") rbp, options(nomem, nostack)
        )
    };

    if rbp == 0 {
        return backtrace;
    }

    // Skip the first stack frame, which is one of the log_backtrace
    // functions below.
    rbp = unsafe { *(rbp as *mut u64) };
    let mut prev = 0_u64;

    for idx in 0..BT_DEPTH {
        if prev == rbp {
            break;
        }
        if rbp == 0 {
            break;
        }
        if rbp < 1024 * 64 {
            break;
        }
        prev = rbp;
        unsafe {
            backtrace[idx] = *((rbp + 8) as *mut u64);
            rbp = *(rbp as *mut u64);
        }
    }

    backtrace
}

fn get_process_name(pid: u64) -> Result<String, moto_rt::ErrorCode> {
    use moto_sys::stats::ProcessStatsV1;

    let mut ps = [ProcessStatsV1::default(); 1];
    assert_eq!(1, ProcessStatsV1::list(pid, &mut ps)?);
    let mut words = ps[0].debug_name().split_whitespace();
    let filename = if let Some(w) = words.next() {
        w
    } else {
        return Err(moto_rt::E_INTERNAL_ERROR);
    }
    .split('/')
    .last()
    .unwrap();
    Ok(filename.to_owned())
}

fn get_thread_trace(
    dbg_handle: moto_sys::SysHandle,
    thread_data: &moto_sys::stats::ThreadDataV1,
) -> [u64; BT_DEPTH] {
    let mut backtrace: [u64; BT_DEPTH] = [0; BT_DEPTH];

    let mut rbp: u64 = thread_data.rbp;
    if rbp == 0 {
        return backtrace;
    }

    let mut prev = 0_u64;

    for idx in 0..BT_DEPTH {
        if prev == rbp {
            break;
        }
        if rbp == 0 {
            break;
        }
        if rbp < 1024 * 64 {
            break;
        }
        prev = rbp;

        // Prepare the place to read into.
        // TODO: we can read 16 bytes at once, not 8 bytes twice.
        let mut remove_val = 0;
        let val_slice = unsafe {
            core::slice::from_raw_parts_mut(&mut remove_val as *mut _ as usize as *mut u8, 8)
        };

        // ip = *(rbp+8)
        match SysRay::dbg_get_mem(dbg_handle, rbp + 8, val_slice) {
            Ok(sz) => {
                assert_eq!(sz, 8);
                backtrace[idx] = remove_val;
            }
            Err(_) => {
                return backtrace;
            }
        }

        // rbp = *rbp
        match SysRay::dbg_get_mem(dbg_handle, rbp, val_slice) {
            Ok(sz) => {
                assert_eq!(sz, 8);
                rbp = remove_val;
            }
            Err(_) => {
                return backtrace;
            }
        }
    }

    backtrace
}

fn print_stack_trace(proc_name: &str, dbg_handle: moto_sys::SysHandle, tid: u64) {
    let thread_data = SysRay::dbg_get_thread_data_v1(dbg_handle, tid).unwrap();
    println!("# {:?}", thread_data);

    let backtrace = get_thread_trace(dbg_handle, &thread_data);

    use core::fmt::Write;
    let mut writer = String::with_capacity(4096);
    write!(
        &mut writer,
        "# Thread {}: '{}' {:?}({}:{}):",
        thread_data.tid,
        thread_data.thread_name(),
        thread_data.status,
        thread_data.syscall_num,
        thread_data.syscall_op
    )
    .ok();
    write!(&mut writer, "\naddr2line -e {proc_name} \\").ok();
    write!(&mut writer, " \n  0x{:x}", thread_data.ip).ok();
    for addr in backtrace {
        if addr == 0 {
            break;
        }

        if addr > (1_u64 << 40) {
            break;
        }

        write!(&mut writer, " \\\n  0x{:x}", addr).ok();
    }

    let _ = write!(&mut writer, "\n\n");
    println!("{}", writer.as_str());
}

fn cmd_print_stacks(pid: u64) -> Result<(), moto_rt::ErrorCode> {
    let proc_name = get_process_name(pid)?;

    let dbg_handle = match SysRay::dbg_attach(pid) {
        Ok(handle) => handle,
        Err(err) => {
            match err {
                moto_rt::E_NOT_FOUND => {
                    eprintln!("Process with pid {pid} not found.");
                    std::process::exit(1)
                }
                moto_rt::E_NOT_ALLOWED => {
                    eprintln!("Debugging process {pid} '{proc_name}' is not allowed.");
                    eprintln!("In general, it is not allowed to debug system processes, ancestors, and self.");
                    std::process::exit(1)
                }
                _ => {
                    eprintln!("dbg_attach({pid}) failed with {:?}", err);
                    std::process::exit(1)
                }
            }
        }
    };

    // This flags the debuggee as paused, and all debuggee threads
    // will eventually pause.
    SysRay::dbg_pause_process(dbg_handle).unwrap();

    // Sleep a bit to let all running threads to get paused.
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut all_tids = VecDeque::new();

    let mut tids = [0_u64; 64];
    let mut start_tid = 0;
    loop {
        let sz = SysRay::dbg_list_threads(dbg_handle, start_tid + 1, &mut tids).unwrap();
        if sz == 0 {
            break;
        }

        for idx in 0..sz {
            all_tids.push_back(tids[idx]);
            print_stack_trace(&proc_name, dbg_handle, tids[idx]);
        }
        start_tid = tids[sz - 1] + 1;
    }

    // This only flags the process as resumed/running.
    // We still need to resume individual threads.
    SysRay::dbg_resume_process(dbg_handle).unwrap();

    // Resume existing threads.
    while let Some(tid) = all_tids.pop_front() {
        if let Err(err) = SysRay::dbg_resume_thread(dbg_handle, tid) {
            assert!(
                err == moto_rt::E_ALREADY_IN_USE
                    || err == moto_rt::E_NOT_FOUND
                    || err == moto_rt::E_NOT_READY
            );
        }
    }

    // It is possible that a new thread was spawned and paused that we didn't capture
    // above, so to make sure we've resumed all threads, we need to do the loop below.
    // NOTE: start_tid is properly set to the last known thread.
    loop {
        let sz = SysRay::dbg_list_threads(dbg_handle, start_tid + 1, &mut tids).unwrap();
        if sz == 0 {
            break;
        }

        for idx in 0..sz {
            if let Err(err) = SysRay::dbg_resume_thread(dbg_handle, tids[idx]) {
                assert!(
                    err == moto_rt::E_ALREADY_IN_USE
                        || err == moto_rt::E_NOT_FOUND
                        || err == moto_rt::E_NOT_READY
                );
            }
        }
        start_tid = tids[sz - 1] + 1;
    }

    SysRay::dbg_detach(dbg_handle).unwrap();

    assert_eq!(
        moto_sys::SysObj::put(dbg_handle).err().unwrap(),
        moto_rt::E_BAD_HANDLE
    );

    // Sleep a bit to let stdout flush.
    // TODO: remove when stdio flush issue is fixed.
    std::thread::sleep(std::time::Duration::from_millis(50));

    Ok(())
}

fn main() -> Result<(), moto_rt::ErrorCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::PrintStacks(args) => cmd_print_stacks(args.pid),
        Commands::Attach => todo!(),
    }
}
