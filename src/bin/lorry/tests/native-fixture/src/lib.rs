cfg_if::cfg_if! {
    if #[cfg(target_os = "motor")] {
        const TARGET_VALUE: &str = fixture_motor_target_dependency::VALUE;
    } else {
        compile_error!("the native fixture must be built for Motor OS");
    }
}

pub fn value() -> String {
    format!(
        "registry|{}|{TARGET_VALUE}",
        fixture_generated_dependency::BUILD_VALUE
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn library_unit_uses_every_dependency_kind() {
        assert_eq!(super::value(), "registry|build-script|motor-target");
    }
}
