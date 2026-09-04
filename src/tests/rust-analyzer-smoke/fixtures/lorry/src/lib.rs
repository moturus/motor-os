pub fn generated_value() -> u32 {
    generated_dependency::GENERATED
}

pub fn generated_environment() -> &'static str {
    generated_dependency::ENVIRONMENT
}

#[deprecated(note = "lorry flycheck marker")]
fn old_function() {}

pub fn trigger_warning() {
    old_function();
}
