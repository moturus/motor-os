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

// Intercept Ctrl+C ourselves if the OS does not do it for us.
/*
fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\ncaught ^C: exiting.");
                std::process::exit(0);
            }
        }
    }
}
*/

fn print_stack_trace(dbg_handle: moto_sys::SysHandle, tid: u64) {
    let thread_data = SysRay::dbg_get_thread_data_v1(dbg_handle, tid).unwrap();
    println!("print_stack_trace {:?}", thread_data);
}

fn cmd_print_stacks(pid: u64) -> Result<(), moto_sys::ErrorCode> {
    println!("cmd_print_stacks({pid}) - start");
    let dbg_handle = match SysRay::dbg_attach(pid) {
        Ok(handle) => handle,
        Err(err) => match err {
            moto_sys::ErrorCode::NotFound => {
                eprintln!("Process with pid {pid} not found.");
                std::process::exit(1)
            }
            _ => {
                eprintln!("dbg_attach({pid}) failed with {:?}", err);
                std::process::exit(1)
            }
        },
    };

    // This flags the debuggee as paused, and all debuggee threads
    // will eventually pause.
    SysRay::dbg_pause_process(dbg_handle).unwrap();

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
            print_stack_trace(dbg_handle, tids[idx]);
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
                err == moto_sys::ErrorCode::AlreadyInUse
                    || err == moto_sys::ErrorCode::NotFound
                    || err == moto_sys::ErrorCode::NotReady
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
                    err == moto_sys::ErrorCode::AlreadyInUse
                        || err == moto_sys::ErrorCode::NotFound
                        || err == moto_sys::ErrorCode::NotReady
                );
            }
        }
        start_tid = tids[sz - 1] + 1;
    }

    SysRay::dbg_detach(dbg_handle).unwrap();

    assert_eq!(
        moto_sys::SysObj::put(dbg_handle).err().unwrap(),
        moto_sys::ErrorCode::BadHandle
    );

    Ok(())
}

fn main() -> Result<(), moto_sys::ErrorCode> {
    // std::thread::spawn(move || input_listener());

    let cli = Cli::parse();
    // println!("{:#?}", cli);
    match cli.cmd {
        Commands::PrintStacks(args) => cmd_print_stacks(args.pid),
        Commands::Attach => todo!(),
    }
}
