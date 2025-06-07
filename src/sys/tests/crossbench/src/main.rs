#![allow(unexpected_cfgs)]

use clap::Parser;
use hdrhistogram::Histogram;
use rand::{Rng, RngCore};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Path to the file to test.
    #[arg(short, long)]
    fname: String,

    // Number of random reads to perform.
    // More iters often leads to reduced mean/meadian,
    // most likely due to caching/collisions.
    #[arg(short, long, default_value_t = 100)]
    iters: u32,
}

const BLOCK_SIZE: usize = 4096;
const TEST_FILE_SIZE: usize = 1024 * 1024 * 20;

fn main() -> io::Result<()> {
    let args = Args::parse();

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

    #[cfg(target_os = "moturus")]
    let mut file = open_direct(file_path)?;

    assert_eq!(TEST_FILE_SIZE as u64, file.metadata()?.len());

    let layout = std::alloc::Layout::from_size_align(BLOCK_SIZE, BLOCK_SIZE).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    let buffer = unsafe { std::slice::from_raw_parts_mut(ptr, BLOCK_SIZE) };

    let mut rng = rand::thread_rng();
    let mut histogram = Histogram::<u64>::new(3).unwrap();

    println!(
        "Performing {} random reads of {BLOCK_SIZE} bytes...",
        args.iters
    );

    for iter in 0..args.iters {
        let max_offset = (TEST_FILE_SIZE - BLOCK_SIZE) as u64;
        let random_offset = rng.gen_range(0..=max_offset);
        let aligned_offset = (random_offset / BLOCK_SIZE as u64) * BLOCK_SIZE as u64;

        let start = Instant::now();

        #[cfg(target_family = "unix")]
        let bytes_read = read_at(&file, buffer, aligned_offset)?;

        #[cfg(target_os = "moturus")]
        let bytes_read = read_at(&mut file, buffer, aligned_offset)?;

        let duration = start.elapsed();

        histogram.record(duration.as_nanos() as u64).unwrap();

        assert_eq!(bytes_read, BLOCK_SIZE);

        if (iter > 0) && (iter + 1) % (args.iters / 10) == 0 {
            println!("...{}% complete", (iter + 1) * 100 / args.iters);
        }
    }

    println!("\n--- Latency Results (in usec) ---");
    println!("Mean:           {:.2}", histogram.mean() / 1000.0);
    println!("StdDev:         {:.2}", histogram.stdev() / 1000.0);
    println!("Min:            {:.2}", histogram.min() as f64 / 1000.0);
    println!("Max:            {:.2}", histogram.max() as f64 / 1000.0);
    println!("\n--- Percentiles (in usec) ---");
    println!(
        "50th (Median):  {:.2}",
        histogram.value_at_percentile(50.0) as f64 / 1000.0
    );
    println!(
        "90th:           {:.2}",
        histogram.value_at_percentile(90.0) as f64 / 1000.0
    );
    println!(
        "99th:           {:.2}",
        histogram.value_at_percentile(99.0) as f64 / 1000.0
    );
    println!(
        "99.9th:         {:.2}",
        histogram.value_at_percentile(99.9) as f64 / 1000.0
    );
    println!(
        "99.99th:        {:.2}",
        histogram.value_at_percentile(99.99) as f64 / 1000.0
    );

    Ok(())
}

fn create_test_file(path: &Path) -> io::Result<()> {
    println!("Creating test file '{path:?}'.");
    let start = Instant::now();
    let file = File::create(path)?;
    let mut writer = io::BufWriter::new(file);
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; 1024 * 1024]; // Write in 1MB chunks.
    let chunk_count = (TEST_FILE_SIZE / buffer.len()) as u64;

    assert_eq!(0, TEST_FILE_SIZE % buffer.len());

    for _ in 0..chunk_count {
        rng.fill_bytes(&mut buffer);
        writer.write_all(&buffer)?;
    }

    writer.flush()?;
    let elapsed = start.elapsed();
    println!(
        "Created a {chunk_count} MB file in {} milliseconds.",
        elapsed.as_millis()
    );

    Ok(())
}

#[cfg(target_family = "unix")]
fn open_direct(path: &Path) -> io::Result<File> {
    use nix::fcntl::{self, OFlag};
    use nix::sys::stat::Mode;
    use std::os::fd::{FromRawFd, OwnedFd};

    let flags = OFlag::O_RDONLY | OFlag::O_DIRECT;
    let fd = fcntl::open(path, flags, Mode::empty())?;
    Ok(unsafe { File::from(OwnedFd::from_raw_fd(fd)) })
}

#[cfg(target_family = "unix")]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    nix::sys::uio::pread(file, buffer, offset as i64).map_err(io::Error::from)
}

#[cfg(target_os = "moturus")]
fn open_direct(path: &Path) -> io::Result<File> {
    std::fs::File::open(path)
}

#[cfg(target_os = "moturus")]
fn read_at(file: &mut File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use io::Read;
    use io::Seek;

    file.seek(io::SeekFrom::Start(offset))?;
    file.read_exact(buffer)?;
    Ok(buffer.len())
}
