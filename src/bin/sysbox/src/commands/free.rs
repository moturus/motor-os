fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Report PHYSICAL RAM available and used.");
    eprintln!("This is different from `ps`, which reports VIRTUAL RAM usage.");
    eprintln!("usage:\n\tfree [-(b|k|m|g)] [reclaim]\n");
    std::thread::sleep(std::time::Duration::new(0, 1_000_000));
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    if args.len() > 3 {
        print_usage_and_exit(-1)
    }

    let mut reclaim = false;
    if args.len() == 3 {
        if args[2].as_str() == "reclaim" {
            reclaim = true;
        } else {
            print_usage_and_exit(-1);
        }
    }

    let mut shift_bits = 0;
    if args.len() > 1 {
        match args[1].as_str() {
            "-b" => {}
            "--help" => print_usage_and_exit(0),
            "-k" => shift_bits = 10,
            "-m" => shift_bits = 20,
            "-g" => shift_bits = 30,
            "reclaim" => {
                if reclaim {
                    print_usage_and_exit(-1);
                } else {
                    reclaim = true;
                }
            }
            _ => print_usage_and_exit(1),
        }
    }
    if reclaim {
        moto_sys::syscalls::SysMem::reclaim(moto_sys::syscalls::SysHandle::KERNEL).unwrap();
    }

    let stats = moto_sys::stats::MemoryStats::get().unwrap();
    let total = stats.available >> shift_bits;
    let used = stats.used() >> shift_bits;

    println!("               total         used         free        kheap    pages");
    println!(
        "Mem:    {:12} {:12} {:12} {:12}    {}",
        total,
        used,
        total - used,
        stats.heap_total >> shift_bits,
        stats.used_pages,
    );
}
