use clap::Parser;
use moto_sys::SysRay;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    print_stacks: u64,
}

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

fn print_stack_trace(
    _dbg_handle: moto_sys::SysHandle,
    tid: u64,
) -> Result<(), moto_sys::ErrorCode> {
    println!("print_stack_trace {tid}");
    Ok(())
}

fn main() -> Result<(), moto_sys::ErrorCode> {
    // std::thread::spawn(move || input_listener());

    let args = Args::parse();
    let pid = args.print_stacks;

    let dbg_handle = SysRay::dbg_attach(pid)?;
    SysRay::dbg_stop(dbg_handle)?;

    let mut tids = [0_u64; 64];
    let mut start_tid = 0;
    loop {
        let sz = SysRay::dbg_list_threads(dbg_handle, start_tid, &mut tids)?;

        for idx in 0..sz {
            print_stack_trace(dbg_handle, tids[idx])?;
        }
        if sz < tids.len() {
            break;
        }
        assert!(sz > 0);
        start_tid = tids[sz - 1] + 1;
    }

    SysRay::dbg_resume(dbg_handle)?;
    Ok(())
}
