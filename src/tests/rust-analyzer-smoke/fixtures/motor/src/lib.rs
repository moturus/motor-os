#![feature(motor_ext)]

#[cfg(not(target_os = "motor"))]
compile_error!("Motor fixture used the wrong target");

motor_ra_smoke_macro::define_marker!();

pub fn consumes_marker(_: GeneratedByProcMacro) {}

pub fn motor_runtime_version() -> u64 {
    std::os::motor::rt_version()
}
