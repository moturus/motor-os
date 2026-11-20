pub mod config;
pub mod control;
pub mod crypto;
pub mod edit;
mod files;
mod ip;
pub mod prompt;
pub mod schedule;
pub mod tool;

#[cfg(target_os = "motor")]
fn motor_getrandom(bytes: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_sdk::rt::fill_random_bytes(bytes);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

#[cfg(test)]
mod config_tests;

#[cfg(test)]
mod control_tests;

#[cfg(test)]
mod crypto_tests;

#[cfg(target_os = "motor")]
pub mod motor;

#[cfg(target_os = "motor")]
pub(crate) mod motor_files;

#[cfg(target_os = "motor")]
pub(crate) mod motor_ipc;

#[cfg(target_os = "motor")]
pub mod launch;

#[cfg(target_os = "motor")]
pub mod motor_tool;

#[cfg(all(target_os = "motor", feature = "native-tests"))]
pub mod tool_tests;

#[cfg(all(target_os = "motor", feature = "native-tests"))]
pub mod tool_protocol_tests;

#[cfg(all(target_os = "motor", feature = "native-tests"))]
mod tool_startup_tests;
