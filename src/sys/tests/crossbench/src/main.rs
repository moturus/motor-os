#![allow(unexpected_cfgs)]
use clap::Parser;

mod fs;

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

fn main() -> std::io::Result<()> {
    fs::run_benches(Args::parse())
}
