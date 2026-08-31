#![feature(motor_ext)]

#[cfg(not(target_os = "motor"))]
compile_error!("inline Motor fixture used the wrong target");

pub fn motor_runtime_version() -> u64 {
    std::os::motor::rt_version()
}
