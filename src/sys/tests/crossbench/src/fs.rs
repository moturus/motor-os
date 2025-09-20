use std::path::Path;
use std::time::Instant;

const BLOCK_SIZE: usize = 4096;
const TEST_FILE_SIZE: usize = 1024 * 1024 * 20;

pub fn run_benches(args: crate::Args) -> std::io::Result<()> {
    let file_path = Path::new(&args.fname);
    if file_path.exists() {
        // If we re-use an existing file, the numbers sometimes
        // magically improve. Maybe the nvme controller optimizes it?
        println!("Deleting test file '{file_path:?}'.");
        std::fs::remove_file(file_path).unwrap();
    }

    assert!(!file_path.exists());
    create_test_file(file_path)?;

    println!("Opening file with O_DIRECT flag...");

    #[cfg(target_family = "unix")]
    let file = open_direct(file_path)?;

    #[cfg(target_os = "motor")]
    let mut file = open_direct(file_path)?;

    assert_eq!(TEST_FILE_SIZE as u64, file.metadata()?.len());

    let layout = std::alloc::Layout::from_size_align(BLOCK_SIZE, BLOCK_SIZE).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    let buffer = unsafe { std::slice::from_raw_parts_mut(ptr, BLOCK_SIZE) };

    let mut rng = rand::thread_rng();
    let mut histogram = hdrhistogram::Histogram::<u64>::new(3).unwrap();

    println!(
        "Performing {} random reads of {BLOCK_SIZE} bytes...",
        args.iters
    );

    let start = Instant::now();
    for iter in 0..args.iters {
        use rand::Rng;

        let max_offset = (TEST_FILE_SIZE - BLOCK_SIZE) as u64;
        let random_offset = rng.gen_range(0..=max_offset);
        let aligned_offset = random_offset & !(BLOCK_SIZE as u64 - 1);

        let start = Instant::now();

        #[cfg(target_family = "unix")]
        let bytes_read = read_at(&file, buffer, aligned_offset)?;

        #[cfg(target_os = "motor")]
        let bytes_read = read_at(&mut file, buffer, aligned_offset)?;

        let duration = start.elapsed();

        histogram.record(duration.as_nanos() as u64).unwrap();

        assert_eq!(bytes_read, BLOCK_SIZE);

        if (iter > 0) && (iter + 1) % (args.iters / 10) == 0 {
            println!("...{}% complete", (iter + 1) * 100 / args.iters);
        }
    }
    let elapsed = start.elapsed();

    println!("\n--- Random Access Latency Results (in usec) ---");
    println!("Mean:               {:>8.2}", histogram.mean() / 1000.0);
    println!("StdDev:             {:>8.2}", histogram.stdev() / 1000.0);
    println!(
        "Min:                {:>8.2}",
        histogram.min() as f64 / 1000.0
    );
    println!(
        "Max:                {:>8.2}",
        histogram.max() as f64 / 1000.0
    );
    println!(
        "Throughput (MB/s):  {:>8.2}",
        ((args.iters as usize * BLOCK_SIZE) as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0)
    );
    println!("\n--- Percentiles (in usec) ---");
    println!(
        "50th (Median):  {:>8.2}",
        histogram.value_at_percentile(50.0) as f64 / 1000.0
    );
    println!(
        "90th:           {:>8.2}",
        histogram.value_at_percentile(90.0) as f64 / 1000.0
    );
    println!(
        "99th:           {:>8.2}",
        histogram.value_at_percentile(99.0) as f64 / 1000.0
    );
    println!(
        "99.9th:         {:>8.2}",
        histogram.value_at_percentile(99.9) as f64 / 1000.0
    );
    println!(
        "99.99th:        {:>8.2}",
        histogram.value_at_percentile(99.99) as f64 / 1000.0
    );

    println!("\nReading the file sequentially.");
    let mut offset = 0;
    let start = Instant::now();
    while offset < TEST_FILE_SIZE {
        #[cfg(target_family = "unix")]
        let bytes_read = read_at(&file, buffer, offset as u64)?;

        #[cfg(target_os = "motor")]
        let bytes_read = read_at(&mut file, buffer, offset as u64)?;

        assert_eq!(bytes_read, BLOCK_SIZE);
        offset += BLOCK_SIZE;
    }
    let elapsed = start.elapsed();
    println!(
        "Sequential read throughput: {:.3} MB/sec.\n",
        ((TEST_FILE_SIZE >> 20) as f64) / (elapsed.as_secs_f64())
    );

    Ok(())
}

fn create_test_file(path: &Path) -> std::io::Result<()> {
    use rand::RngCore;
    use std::io::Write;

    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; 1024 * 1024]; // Write in 1MB chunks.
    let chunk_count = (TEST_FILE_SIZE / buffer.len()) as u64;

    println!("Creating test file '{path:?}'.");
    let file = std::fs::File::create(path)?;

    let start = Instant::now();
    let mut writer = std::io::BufWriter::new(file);

    assert_eq!(0, TEST_FILE_SIZE % buffer.len());

    for _ in 0..chunk_count {
        rng.fill_bytes(&mut buffer);
        writer.write_all(&buffer)?;
    }

    writer.flush()?;
    let elapsed = start.elapsed();
    println!(
        "\nCreated a {chunk_count} MB file in {} milliseconds.",
        elapsed.as_millis()
    );
    println!(
        "Sequential write throughput: {:.3} MB/sec.\n",
        (chunk_count as f64) / (elapsed.as_secs_f64())
    );

    Ok(())
}

#[cfg(target_family = "unix")]
fn open_direct(path: &Path) -> std::io::Result<std::fs::File> {
    use nix::fcntl::{self, OFlag};
    use nix::sys::stat::Mode;
    use std::os::fd::{FromRawFd, OwnedFd};

    let flags = OFlag::O_RDONLY | OFlag::O_DIRECT;
    let fd = fcntl::open(path, flags, Mode::empty())?;
    Ok(unsafe { std::fs::File::from(OwnedFd::from_raw_fd(fd)) })
}

#[cfg(target_family = "unix")]
fn read_at(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    nix::sys::uio::pread(file, buffer, offset as i64).map_err(std::io::Error::from)
}

#[cfg(target_os = "motor")]
fn open_direct(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(target_os = "motor")]
fn read_at(file: &mut std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::io::Read;
    use std::io::Seek;

    file.seek(std::io::SeekFrom::Start(offset))?;
    file.read_exact(buffer)?;
    Ok(buffer.len())
}
