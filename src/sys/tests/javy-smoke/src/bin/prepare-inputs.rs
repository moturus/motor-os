#[path = "../inputs.rs"]
#[allow(dead_code)]
mod inputs;

fn main() -> std::io::Result<()> {
    let root = std::env::args_os().nth(1).expect("output directory");
    inputs::write(std::path::Path::new(&root))
}
