#[cfg(target_os = "motor")]
mod compiler;
#[cfg(target_os = "motor")]
mod editor;
#[cfg(target_os = "motor")]
mod helix;
#[cfg(target_os = "motor")]
mod quickjs;
#[cfg(target_os = "motor")]
mod rustfmt;
#[cfg(target_os = "motor")]
mod support;
#[cfg(target_os = "motor")]
mod utilities;

fn main() {
    #[cfg(target_os = "motor")]
    {
        let selected = std::env::args().nth(1);
        let checks: &[(&str, fn())] = &[
            ("rustfmt", rustfmt::run),
            ("compiler", compiler::run),
            ("utilities", utilities::run),
            ("helix", helix::run),
            ("quickjs", quickjs::run),
        ];
        assert!(
            selected
                .as_ref()
                .is_none_or(|s| checks.iter().any(|(name, _)| name == s))
        );
        for (name, run) in checks {
            if selected.as_ref().is_none_or(|s| s == name) {
                println!("installed toolchain: {name}");
                run();
            }
        }
        println!("installed toolchain: PASS");
    }
}
