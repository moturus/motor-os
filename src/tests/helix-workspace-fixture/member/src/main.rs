mod definitions;

fn local_value() -> u32 {
    definitions::MODULE_VALUE
}

fn main() {
    let _value = local_value();
}
