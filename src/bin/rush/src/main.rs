#![feature(io_error_more)]

fn main() {
    let (args, script) = moto_rush::parse_args(std::env::args().collect());
    moto_rush::execute(args, script);
}
