fn main() {
    let (red, blue) = shared::features();
    println!("{} {} {red} {blue}", file!(), shared::source());
}
